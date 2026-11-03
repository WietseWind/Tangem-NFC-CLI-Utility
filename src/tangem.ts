import { CardConnection, Pcsc } from './pcsc.ts'
import { Session, TangemError, type SessionOptions, type UserCode } from './session.ts'
import { Tlv, cstring, hex, u32, u8 } from './tlv.ts'
import { parseCard, parseWallet, type CardInfo, type Wallet } from './card.ts'
import { sha256 } from './crypto.ts'
import {
  DEFAULT_ACCESS_CODE, DEFAULT_PASSCODE, FW, INS, READ_MODE, SIGNING_METHOD_SIGN_HASH, SW, TAG,
  WALLET_SETTINGS, type Curve,
} from './constants.ts'

export interface ConnectOptions extends SessionOptions {
  /** Reader index or name substring; default: first reader with a card. */
  reader?: string
  timeoutMs?: number
  signal?: AbortSignal
}

/**
 * High level Tangem card API.
 *
 *   const tangem = await Tangem.connect()
 *   const card = await tangem.scan()
 *   tangem.close()
 */
export class Tangem {
  card?: CardInfo

  private constructor(readonly pcsc: Pcsc, readonly conn: CardConnection, readonly session: Session) {}

  static listReaders(): string[] {
    const pcsc = Pcsc.open()
    try { return pcsc.listReaders() } finally { pcsc.close() }
  }

  /** Wait for a card on a reader and open a session. */
  static async connect(opts: ConnectOptions = {}): Promise<Tangem> {
    const pcsc = Pcsc.open()
    try {
      const conn = await pcsc.waitForCard({ reader: opts.reader, timeoutMs: opts.timeoutMs, signal: opts.signal })
      const session = new Session(conn, opts)
      session.uid = conn.uid()
      return new Tangem(pcsc, conn, session)
    } catch (e) {
      pcsc.close()
      throw e
    }
  }

  /** READ card + (fw ≥ 4) wallet list. */
  async scan(): Promise<CardInfo> {
    const card = await this.readCard()
    if (card.firmware.gte(FW.multiwallet) && card.status !== 'notPersonalized') {
      // READ (mode 1) works without the right code; reading wallets doesn't.
      if (card.isAccessCodeSet && this.session.accessCode === DEFAULT_ACCESS_CODE) throw accessCodeError()
      card.wallets = await this.readWallets()
      // fw ≥ 4 reports 1 (= personalized) at card level; wallet state lives per slot.
      if (card.status === 'empty' || card.status === 'loaded') card.status = card.wallets.length ? 'loaded' : 'empty'
    }
    return card
  }

  async readCard(): Promise<CardInfo> {
    const res = await this.#mapErrors(
      () => this.session.send(INS.READ, [
        [TAG.PIN, this.session.accessCodeHash],
        [TAG.INTERACTION_MODE, u8(READ_MODE.CARD)],
      ]),
      { [SW.INVALID_PARAMS]: accessCodeError },
    )
    const card = parseCard(res.tlv, this.session.accessCode === DEFAULT_ACCESS_CODE)
    card.uid = this.session.uid?.toString('hex').toUpperCase()
    this.card = card
    this.session.adoptCardPolicy(card.encryptionAllowed)
    return card
  }

  /** All wallets (fw ≥ 4 multi-wallet cards). Legacy cards: wallets come from readCard(). */
  async readWallets(): Promise<Wallet[]> {
    const card = this.#requireCard()
    if (!card.firmware.gte(FW.multiwallet)) return card.wallets
    this.#assertLegacySecureChannel(card)
    const wallets: Wallet[] = []
    let received = 0
    while (received < card.maxWallets) {
      const res = await this.#mapErrors(
        () => this.session.send(INS.READ, [
          [TAG.INTERACTION_MODE, u8(READ_MODE.WALLETS_LIST)],
          [TAG.PIN, this.#pin(this.session.accessCode, DEFAULT_ACCESS_CODE)],
          [TAG.CARD_ID, hex(card.cardId)],
          [TAG.WALLET_INDEX, received > 0 ? u8(received) : null],
        ]),
        { [SW.INVALID_PARAMS]: accessCodeError },
      )
      const entries = res.tlv.all(TAG.CARD_WALLET)
      if (entries.length === 0) break
      received += entries.length
      for (const entry of entries) {
        const wallet = parseWallet(new Tlv(entry), card)
        if (wallet) wallets.push(wallet)
      }
    }
    card.wallets = wallets.sort((a, b) => a.index - b.index)
    return card.wallets
  }

  /** Read one wallet, optionally deriving a child key on-card (HD wallets, fw ≥ 4.39). */
  async readWallet(index: number, derivationPath?: string): Promise<Wallet> {
    const card = this.#requireCard()
    this.#assertLegacySecureChannel(card)
    if (!card.firmware.gte(FW.multiwallet)) {
      const wallet = card.wallets.find(w => w.index === index)
      if (!wallet) throw new TangemError('Wallet not found', SW.WALLET_NOT_FOUND)
      if (derivationPath) throw new TangemError('This card does not support HD derivation')
      return wallet
    }
    if (derivationPath && !card.firmware.gte(FW.hdWallet)) throw new TangemError('This card does not support HD derivation')
    const res = await this.session.send(INS.READ, [
      [TAG.INTERACTION_MODE, u8(READ_MODE.WALLET)],
      [TAG.WALLET_INDEX, u8(index)],
      [TAG.PIN, this.#pin(this.session.accessCode, DEFAULT_ACCESS_CODE)],
      [TAG.CARD_ID, hex(card.cardId)],
      [TAG.WALLET_HD_PATH, derivationPath ? encodeDerivationPath(derivationPath) : null],
    ])
    const wallet = parseWallet(res.tlv, card)
    if (!wallet) throw new TangemError('Wallet not found', SW.WALLET_NOT_FOUND)
    return wallet
  }

  /** First free wallet slot, or undefined when the card is full / can't create. */
  freeWalletIndex(): number | undefined {
    const card = this.#requireCard()
    if (!card.firmware.gte(FW.multiwallet)) return card.status === 'empty' ? 0 : undefined
    const used = new Set(card.wallets.map(w => w.index))
    for (let i = 0; i < card.maxWallets; i++) if (!used.has(i)) return i
    return undefined
  }

  /** Why a wallet can't be created right now (undefined = it can). */
  createBlocker(curve?: Curve): string | undefined {
    const card = this.#requireCard()
    if (card.status === 'notPersonalized') return 'Card is not personalized'
    if (!card.isActivated) return 'Card is not activated'
    if (card.firmware.gte(FW.v8)) return 'Firmware ≥ 8.59 (new secure channel) is not supported yet'
    if (!card.firmware.gte(FW.multiwallet)) {
      if (card.status === 'loaded') return 'Card already holds its (single) wallet'
      if (card.status === 'purged') return 'Wallet was purged and this card cannot create a new one'
    } else if (!card.firmware.gte(FW.createWalletResponse) && !card.settings.includes('allowSelectBlockchain')) {
      return 'Card does not allow creating wallets (AllowSelectBlockchain not set)'
    }
    if (this.freeWalletIndex() === undefined) return card.maxWallets > 1 ? `All ${card.maxWallets} wallet slots are in use` : 'Card already holds a wallet'
    if (curve && !card.supportedCurves.includes(curve)) return `Curve ${curve} not supported (supported: ${card.supportedCurves.join(', ')})`
    return undefined
  }

  /** CREATE_WALLET. Legacy cards (fw < 4) always use their default curve. */
  async createWallet(opts: { curve?: Curve; index?: number } = {}): Promise<Wallet> {
    const card = this.#requireCard()
    const legacy = !card.firmware.gte(FW.multiwallet)
    const curve = (legacy ? card.defaultCurve : opts.curve ?? 'secp256k1') as Curve
    const blocker = this.createBlocker(curve)
    if (blocker) throw new TangemError(blocker)
    const index = opts.index ?? this.freeWalletIndex()!
    if (card.wallets.some(w => w.index === index)) throw new TangemError(`Wallet slot #${index} is already in use`, SW.WALLET_ALREADY_EXISTS)
    if (index >= card.maxWallets) throw new TangemError(`Wallet index ${index} out of range (0-${card.maxWallets - 1})`)
    this.#assertUserCodes(card)

    const res = await this.#mapErrors(
      () => this.session.send(INS.CREATE_WALLET, [
        [TAG.PIN, this.#pin(this.session.accessCode, DEFAULT_ACCESS_CODE)],
        [TAG.PIN2, this.#pin(this.session.passcode, DEFAULT_PASSCODE)],
        [TAG.CVC, this.#cvc(card)],
        [TAG.CARD_ID, hex(card.cardId)],
        ...(legacy ? [] : [
          [TAG.SETTINGS_MASK, u32(WALLET_SETTINGS.isReusable)],
          [TAG.CURVE_ID, cstring(curve)],
          [TAG.SIGNING_METHOD, u8(SIGNING_METHOD_SIGN_HASH)],
          [TAG.WALLET_INDEX, u8(index)],
        ] as Array<[number, Buffer]>),
      ]),
      this.#codeErrors(card),
    )

    const wallet: Wallet = (card.firmware.gte(FW.createWalletResponse) ? parseWallet(res.tlv, card) : undefined) ?? {
      index: res.tlv.int(TAG.WALLET_INDEX) ?? index,
      status: 'loaded',
      curve,
      publicKey: res.tlv.hex(TAG.WALLET_PUBLIC_KEY) ?? '',
      isPermanent: legacy && card.settings.includes('permanentWallet'),
      isImported: false,
      hasBackup: false,
    }
    if (!wallet.publicKey) throw new TangemError('CREATE_WALLET returned no public key')
    wallet.curve ??= curve
    card.wallets = [...card.wallets.filter(w => w.index !== wallet.index), wallet].sort((a, b) => a.index - b.index)
    if (legacy) card.status = 'loaded'
    return wallet
  }

  /**
   * Why a wallet can't be deleted (undefined = it can).
   * `force` skips the client-side permanent-wallet check and leaves the decision to the card.
   */
  purgeBlocker(index: number, force = false): string | undefined {
    const card = this.#requireCard()
    if (card.firmware.gte(FW.v8)) return 'Firmware ≥ 8.59 (new secure channel) is not supported yet'
    const wallet = card.wallets.find(w => w.index === index)
    if (!wallet) return `No wallet at index ${index}`
    if (wallet.isPermanent && !force) return 'Wallet is permanent: this card prohibits deleting it (--force lets the card decide)'
    return undefined
  }

  /** PURGE_WALLET — irreversibly destroys the private key. */
  async purgeWallet(index: number, opts: { force?: boolean } = {}): Promise<void> {
    const card = this.#requireCard()
    const blocker = this.purgeBlocker(index, opts.force)
    if (blocker) throw new TangemError(blocker)
    const permanent = card.wallets.find(w => w.index === index)?.isPermanent
    this.#assertUserCodes(card)
    await this.#mapErrors(
      () => this.session.send(INS.PURGE_WALLET, [
        [TAG.WALLET_INDEX, u8(index)],
        [TAG.PIN, this.#pin(this.session.accessCode, DEFAULT_ACCESS_CODE)],
        [TAG.PIN2, this.#pin(this.session.passcode, DEFAULT_PASSCODE)],
        [TAG.CVC, this.#cvc(card)],
        [TAG.CARD_ID, hex(card.cardId)],
      ]),
      {
        ...this.#codeErrors(card),
        // Seen live (fw 4.52): a permanent wallet is refused with 6286 after the security delay
        ...(permanent && { [SW.ERROR_PROCESSING_COMMAND]: () => new TangemError('Card refused: the wallet is permanent (SW 6286)', SW.ERROR_PROCESSING_COMMAND) }),
      },
    )
    card.wallets = card.wallets.filter(w => w.index !== index)
    if (!card.firmware.gte(FW.multiwallet)) card.status = card.settings.includes('isReusable') ? 'empty' : 'purged'
  }

  /** Release the card and wait until it's taken off the reader. */
  async waitForRemoval(): Promise<void> {
    this.conn.disconnect()
    await this.pcsc.waitForRemoval(this.conn.reader)
  }

  close() {
    try { this.conn.disconnect() } finally { this.pcsc.close() }
  }

  #requireCard(): CardInfo {
    if (!this.card) throw new Error('Read the card first (scan / readCard)')
    return this.card
  }

  #assertLegacySecureChannel(card: CardInfo) {
    if (card.firmware.gte(FW.v8)) throw new TangemError('Firmware ≥ 8.59 (new secure channel) is not supported yet')
  }

  /**
   * Fail before talking to the card when we already know a code is missing:
   * every wrong PIN2/CVC makes the card slower to respond until the right one is given.
   */
  #assertUserCodes(card: CardInfo) {
    const needs: UserCode[] = []
    if (card.isPasscodeSet && this.session.passcode === DEFAULT_PASSCODE) needs.push('passcode')
    if (card.settings.includes('useCvc') && !this.session.cvc) needs.push('cvc')
    if (needs.length) throw new TangemError(`${describeCodes(needs)} required`, undefined, needs)
  }

  /** Map the card's wrong-code answers to errors listing which codes to ask for. */
  #codeErrors(card: CardInfo) {
    const needs: UserCode[] = card.isPasscodeSet === false ? [] : ['passcode']
    if (card.settings.includes('useCvc')) needs.push('cvc')
    if (!needs.length) needs.push('passcode')
    const error = () => new TangemError(`${describeCodes(needs)} is wrong or required`, SW.INVALID_PASSCODE, needs)
    return { [SW.INVALID_PARAMS]: error, [SW.INVALID_PASSCODE]: error }
  }

  #cvc(card: CardInfo) {
    return card.settings.includes('useCvc') && this.session.cvc ? Buffer.from(this.session.cvc, 'utf8') : null
  }

  /** PIN hash TLV value, omitted where firmware treats a missing PIN as default (fw ≥ 4.34). */
  #pin(code: string, defaultCode: string) {
    const card = this.#requireCard()
    if (card.firmware.gte(FW.defaultPinsOptional) && code === defaultCode) return null
    return sha256(code)
  }

  async #mapErrors<T>(fn: () => Promise<T>, map: Partial<Record<number, () => TangemError>>): Promise<T> {
    try {
      return await fn()
    } catch (e) {
      if (e instanceof TangemError && e.sw !== undefined && map[e.sw]) throw map[e.sw]!()
      throw e
    }
  }
}

const accessCodeError = () => new TangemError('Access code (PIN1) is wrong or required', SW.INVALID_ACCESS_CODE, ['accessCode'])

/** "m/44'/144'/0'/0/0" → 4-byte big-endian indices (hardened = | 0x80000000). */
export function encodeDerivationPath(path: string): Buffer {
  const parts = path.trim().replace(/^m\/?/i, '').split('/').filter(Boolean)
  if (parts.length === 0 || parts.length > 5) throw new Error(`Invalid derivation path "${path}" (1-5 levels)`)
  return Buffer.concat(parts.map(p => {
    const m = p.match(/^(\d+)(['hH]?)$/)
    if (!m) throw new Error(`Invalid derivation path segment "${p}"`)
    const n = Number(m[1])
    if (n >= 0x80000000) throw new Error(`Derivation index out of range: ${p}`)
    return u32(m[2] ? (n | 0x80000000) >>> 0 : n)
  }))
}

const describeCodes = (needs: UserCode[]) =>
  needs.map(n => (n === 'accessCode' ? 'Access code (PIN1)' : n === 'passcode' ? 'Passcode (PIN2)' : 'CVC')).join(' or ')
