import {
  BACKUP_STATUS, CARD_SETTINGS, TERMINAL_LINK, CARD_STATUS, CURVES, FW, PRODUCT_MASK, SIGNING_METHODS, TAG, USER_SETTINGS,
  WALLET_AVAILABLE, WALLET_SETTINGS, WALLET_STATUS, type CardStatus, type Curve, type EncryptionMode,
} from './constants.ts'
import { Tlv } from './tlv.ts'

export class Firmware {
  readonly major: number
  readonly minor: number
  readonly patch: number
  /** 'release' (r), 'sdk' (d SDK) or 'special' */
  readonly type: 'release' | 'sdk' | 'special'

  constructor(readonly raw: string) {
    const clean = raw.replace(/\0/g, '')
    const [major = 0, minor = 0, patch = 0] = (clean.match(/^[\d.]+/)?.[0] ?? '').split('.').map(Number)
    this.major = major
    this.minor = minor
    this.patch = patch
    const suffix = clean.replace(/^[\d.]+/, '').trim()
    this.type = suffix === '' || suffix === 'r' ? 'release' : suffix === 'd SDK' ? 'sdk' : 'special'
  }

  /** Compare against [major, minor] feature thresholds. */
  gte([major, minor]: readonly [number, number]) {
    return this.major !== major ? this.major > major : this.minor >= minor
  }

  toString() { return this.raw.replace(/\0/g, '') }
  toJSON() { return this.toString() }
}

export interface Wallet {
  index: number
  status: string
  curve?: Curve | string
  /** Hex, as returned by the card (compressed for fw ≥ 4, uncompressed on older cards). */
  publicKey: string
  chainCode?: string
  signedHashes?: number
  remainingSignatures?: number
  isPermanent: boolean
  isImported: boolean
  hasBackup: boolean
}

export interface CardInfo {
  cardId: string
  cardIdValid: boolean
  status: CardStatus
  firmware: Firmware
  manufacturer?: string
  issuer?: string
  batchId?: string
  manufactureDate?: string
  cardPublicKey?: string
  issuerPublicKey?: string
  uid?: string
  health: number
  isActivated: boolean
  /** Raw settings mask + decoded flag names. */
  settingsMask: number
  settings: string[]
  userSettings: string[]
  securityDelayMs: number
  maxWallets: number
  /** Wallet used when a command doesn't name one (fw ≥ 4) */
  defaultWalletIndex?: number
  /** Legacy cards: signatures allowed per wallet before it's wiped */
  maxSignatures?: number
  /** Linked terminal (lets SIGN skip the security delay) */
  terminalLink?: string
  defaultCurve?: string
  supportedCurves: Curve[]
  signingMethods: string[]
  isAccessCodeSet?: boolean
  isPasscodeSet?: boolean
  encryptionAllowed: EncryptionMode[]
  backupStatus?: string
  backupCount?: number
  productMask: string[]
  blockchain?: string
  token?: { symbol?: string; name?: string; contract?: string; decimals?: number }
  /** Legacy (fw < 4) cards report their single wallet in the READ response. */
  wallets: Wallet[]
}

const flags = (mask: number, table: Record<string, number>) =>
  Object.entries(table).filter(([, bit]) => (mask & bit) === bit).map(([name]) => name)

const has = (mask: number, bit: number) => (mask & bit) === bit

export function parseCard(tlv: Tlv, accessCodeIsDefault: boolean): CardInfo {
  const firmware = new Firmware(tlv.str(TAG.FIRMWARE_VERSION) ?? '0.0')
  const cardData = tlv.nested(TAG.CARD_DATA) ?? new Tlv([])
  const mask = tlv.int(TAG.SETTINGS_MASK) ?? 0
  const status = CARD_STATUS[tlv.int(TAG.STATUS) ?? -1] ?? 'notPersonalized'
  const defaultCurve = tlv.str(TAG.CURVE_ID)
  const cardId = tlv.hex(TAG.CARD_ID) ?? ''

  const wallets: Wallet[] = []
  if (!firmware.gte(FW.multiwallet) && status === 'loaded' && tlv.has(TAG.WALLET_PUBLIC_KEY)) {
    wallets.push({
      index: 0,
      status: 'loaded',
      curve: defaultCurve,
      publicKey: tlv.hex(TAG.WALLET_PUBLIC_KEY)!,
      signedHashes: tlv.int(TAG.WALLET_SIGNED_HASHES),
      remainingSignatures: tlv.int(TAG.WALLET_REMAINING_SIGNATURES),
      isPermanent: has(mask, CARD_SETTINGS.permanentWallet!),
      isImported: false,
      hasBackup: false,
    })
  }

  const date = cardData.bytes(TAG.MANUFACTURE_DATE_TIME)
  const productMask = cardData.int(TAG.PRODUCT_MASK) ?? tlv.int(TAG.PRODUCT_MASK)
  const tokenDecimals = cardData.int(TAG.TOKEN_DECIMAL)
  const token = {
    symbol: cardData.str(TAG.TOKEN_SYMBOL),
    name: cardData.str(TAG.TOKEN_NAME),
    contract: cardData.str(TAG.TOKEN_CONTRACT_ADDRESS),
    decimals: tokenDecimals,
  }

  return {
    cardId,
    cardIdValid: luhn(cardId),
    status,
    firmware,
    manufacturer: tlv.str(TAG.MANUFACTURER_NAME),
    issuer: cardData.str(TAG.ISSUER_NAME),
    batchId: cardData.hex(TAG.BATCH_ID),
    manufactureDate: date && date.length >= 4
      ? `${date.readUInt16BE(0)}-${String(date[2]).padStart(2, '0')}-${String(date[3]).padStart(2, '0')}`
      : undefined,
    cardPublicKey: tlv.hex(TAG.CARD_PUBLIC_KEY),
    issuerPublicKey: tlv.hex(TAG.ISSUER_PUBLIC_KEY),
    health: tlv.int(TAG.HEALTH) ?? 0,
    isActivated: !tlv.has(TAG.IS_ACTIVATED), // tag present = activation still required
    settingsMask: mask,
    settings: flags(mask, CARD_SETTINGS),
    userSettings: flags(tlv.int(TAG.USER_SETTINGS_MASK) ?? 0, USER_SETTINGS),
    securityDelayMs: (tlv.int(TAG.PAUSE_BEFORE_PIN2) ?? 0) * 10,
    maxWallets: tlv.int(TAG.WALLETS_COUNT) ?? 1,
    defaultWalletIndex: tlv.int(TAG.WALLET_INDEX),
    maxSignatures: tlv.int(TAG.MAX_SIGNATURES),
    terminalLink: tlv.has(TAG.TERMINAL_LINK_STATE) ? TERMINAL_LINK[tlv.int(TAG.TERMINAL_LINK_STATE) ?? -1] ?? 'unknown'
      : tlv.has(TAG.IS_LINKED) ? 'linked' : undefined,
    defaultCurve,
    supportedCurves: supportedCurves(firmware, defaultCurve),
    signingMethods: signingMethods(tlv.int(TAG.SIGNING_METHOD)),
    // Older firmware doesn't report it: READ succeeded, so it's set iff we used a non-default code.
    isAccessCodeSet: firmware.gte(FW.userCodeStatuses) ? !tlv.has(TAG.PIN_IS_DEFAULT) : !accessCodeIsDefault,
    isPasscodeSet: firmware.gte(FW.v8) ? undefined : firmware.gte(FW.passcodeStatus) ? !tlv.has(TAG.PIN2_IS_DEFAULT) : undefined,
    encryptionAllowed: [
      ...(has(mask, CARD_SETTINGS.allowUnencrypted!) ? ['none' as const] : []),
      ...(has(mask, CARD_SETTINGS.allowFastEncryption!) ? ['fast' as const] : []),
      'strong' as const,
    ],
    backupStatus: tlv.has(TAG.BACKUP_STATUS) ? BACKUP_STATUS[tlv.int(TAG.BACKUP_STATUS)!] : undefined,
    backupCount: tlv.int(TAG.BACKUP_COUNT),
    productMask: productMask !== undefined ? flags(productMask, PRODUCT_MASK) : [],
    blockchain: cardData.str(TAG.BLOCKCHAIN_NAME),
    token: Object.values(token).some(v => v !== undefined) ? token : undefined,
    wallets,
  }
}

/** Parse one wallet TLV (CREATE_WALLET response, READ wallet / wallet list entry). Returns undefined for empty slots. */
export function parseWallet(tlv: Tlv, card: Pick<CardInfo, 'settingsMask'>): Wallet | undefined {
  const statusRaw = tlv.int(TAG.STATUS) ?? 0x02
  if (!WALLET_AVAILABLE.has(statusRaw)) return undefined
  const walletMask = tlv.int(TAG.SETTINGS_MASK)
  return {
    index: tlv.int(TAG.WALLET_INDEX) ?? 0,
    status: WALLET_STATUS[statusRaw] ?? `0x${statusRaw.toString(16)}`,
    curve: tlv.str(TAG.CURVE_ID),
    publicKey: tlv.hex(TAG.WALLET_PUBLIC_KEY) ?? '',
    chainCode: tlv.hex(TAG.WALLET_HD_CHAIN),
    signedHashes: tlv.int(TAG.WALLET_SIGNED_HASHES),
    isPermanent: walletMask !== undefined
      ? has(walletMask, WALLET_SETTINGS.isPermanent)
      : has(card.settingsMask, CARD_SETTINGS.permanentWallet!),
    isImported: statusRaw === 0x42 || statusRaw === 0xc2,
    hasBackup: (statusRaw & 0x80) === 0x80,
  }
}

function supportedCurves(fw: Firmware, defaultCurve?: string): Curve[] {
  if (!fw.gte(FW.multiwallet)) return defaultCurve && (CURVES as readonly string[]).includes(defaultCurve) ? [defaultCurve as Curve] : []
  if (!fw.gte(FW.bls)) return ['secp256k1', 'ed25519', 'secp256r1']
  if (!fw.gte(FW.ed25519Slip0010)) return ['secp256k1', 'ed25519', 'secp256r1', 'bip0340', 'bls12381_G2', 'bls12381_G2_AUG', 'bls12381_G2_POP']
  return [...CURVES]
}

function signingMethods(value?: number): string[] {
  if (value === undefined) return []
  // High bit set = set of methods (bit n = method n); otherwise a single method id.
  const set = value & 0x80 ? value & 0x7f : 1 << value
  return Object.entries(SIGNING_METHODS).filter(([, id]) => set & (1 << id)).map(([name]) => name)
}

/** CID check digit: Luhn over hex digits (Tangem spec 2.1.3.1). */
export function luhn(cardId: string): boolean {
  if (!/^[0-9A-F]{16}$/i.test(cardId)) return false
  let sum = 0
  const id = cardId.toUpperCase()
  for (let i = 0; i < id.length; i++) {
    const c = id[id.length - 1 - i]!
    let d = c >= '0' && c <= '9' ? c.charCodeAt(0) - 48 : c.charCodeAt(0) - 65
    if (i % 2 === 1) d *= 2
    sum += d > 9 ? d - 9 : d
  }
  return sum % 10 === 0
}

export const formatCardId = (id: string) => id.replace(/(.{4})(?=.)/g, '$1 ')
