import type { CardConnection } from './pcsc.ts'
import { ENCRYPTION, INS, SW, SW_MESSAGE, TAG, isSuccess, type EncryptionMode } from './constants.ts'
import { aesDecrypt, aesEncrypt, crc16a, ecdhKeyPair, protocolKey, randomBytes, sha256 } from './crypto.ts'
import { Tlv, buildTlv } from './tlv.ts'

/** User codes a command may need (re-)entered. */
export type UserCode = 'accessCode' | 'passcode' | 'cvc'

export class TangemError extends Error {
  /**
   * @param needs codes that are missing or wrong; supplying them may make a retry succeed
   */
  constructor(message: string, readonly sw?: number, readonly needs: UserCode[] = []) {
    super(message)
    this.name = 'TangemError'
  }
  static fromSw(sw: number, ins?: number) {
    const swHex = sw.toString(16).toUpperCase().padStart(4, '0')
    const cmd = ins !== undefined ? Object.entries(INS).find(([, v]) => v === ins)?.[0] : undefined
    return new TangemError(`${SW_MESSAGE[sw] ?? 'Unknown status'} (SW ${swHex}${cmd ? `, ${cmd}` : ''})`, sw)
  }
}

export interface SessionOptions {
  /** PIN1 / access code (plain text). Default '000000'. */
  accessCode?: string
  /** PIN2 / passcode (plain text). Default '000'. */
  passcode?: string
  /** 3-digit CVC printed on cards personalized with UseCVC. */
  cvc?: string
  /** Start with this encryption mode; 'auto' starts unencrypted and upgrades on SW_NEED_ENCRYPTION. */
  encryption?: EncryptionMode | 'auto'
  /** Called for every raw APDU exchanged (plain-text view, before encryption / after decryption). */
  onApdu?: (dir: '>' | '<', data: Buffer, note?: string) => void
  /** Called while the card enforces a security delay. */
  onSecurityDelay?: (remainingSeconds: number) => void
}

export interface Response {
  sw: number
  data: Buffer
  tlv: Tlv
}

const ORDER: EncryptionMode[] = ['none', 'fast', 'strong']

/**
 * One NFC session with a card: APDU framing, encryption (none / fast / strong),
 * security delay handling and automatic encryption upgrade.
 */
export class Session {
  encryption: EncryptionMode
  accessCode: string
  passcode: string
  cvc?: string
  /** ISO 14443-3 UID (from OPEN_SESSION or the reader). */
  uid?: Buffer
  #key?: Buffer
  #upgradable: boolean

  constructor(readonly conn: CardConnection, readonly opts: SessionOptions = {}) {
    this.accessCode = opts.accessCode ?? '000000'
    this.passcode = opts.passcode ?? '000'
    this.cvc = opts.cvc
    this.encryption = opts.encryption && opts.encryption !== 'auto' ? opts.encryption : 'none'
    this.#upgradable = !opts.encryption || opts.encryption === 'auto'
  }

  get accessCodeHash() { return sha256(this.accessCode) }
  get passcodeHash() { return sha256(this.passcode) }

  /** Switch encryption mode; forces a new OPEN_SESSION on the next command. */
  setEncryption(mode: EncryptionMode) {
    if (mode !== this.encryption) this.#key = undefined
    this.encryption = mode
  }

  /** After READ: jump straight to the weakest mode the card accepts (saves a NEED_ENCRYPTION round trip). */
  adoptCardPolicy(allowed: EncryptionMode[]) {
    if (!this.#upgradable || allowed.includes(this.encryption)) return
    const next = ORDER.find(m => ORDER.indexOf(m) > ORDER.indexOf(this.encryption) && allowed.includes(m))
    if (next) this.setEncryption(next)
  }

  /** Changing the access code changes the session key too. */
  setAccessCode(code: string) {
    this.accessCode = code
    this.#key = undefined
  }

  async send(ins: number, payload: Buffer | Array<[number, Uint8Array | null | undefined]>, p2 = 0): Promise<Response> {
    const tlv = Array.isArray(payload) ? buildTlv(payload) : payload
    while (true) {
      if (this.encryption !== 'none' && !this.#key) await this.#openSession()
      const res = await this.#exchange(ins, tlv, p2)
      if (res.sw === SW.NEED_ENCRYPTION && this.#upgradable && this.encryption !== 'strong') {
        this.setEncryption(ORDER[ORDER.indexOf(this.encryption) + 1]!)
        this.opts.onApdu?.('<', Buffer.alloc(0), `need encryption → retry with ${this.encryption}`)
        continue
      }
      if (!isSuccess(res.sw)) throw TangemError.fromSw(res.sw, ins)
      return res
    }
  }

  async #exchange(ins: number, tlv: Buffer, p2: number): Promise<Response> {
    const encrypted = this.encryption !== 'none' && ins !== INS.OPEN_SESSION
    this.opts.onApdu?.('>', tlv, `${insName(ins)}${encrypted ? ` [${this.encryption}]` : ''}`)
    const body = encrypted ? aesEncrypt(this.#key!, Buffer.concat([u16(tlv.length), crc16a(tlv), tlv])) : tlv
    const apdu = frame(ins, encrypted ? ENCRYPTION[this.encryption] : 0, p2, body)

    let raw: Buffer
    while (true) {
      raw = this.conn.transmit(apdu)
      if (raw.length < 2) throw new TangemError('Empty response from card')
      const sw = raw.readUInt16BE(raw.length - 2)
      if (sw !== SW.NEED_PAUSE) break
      // Security delay: card answers ~every second with remaining time (unencrypted); resend the same APDU.
      const pause = new Tlv(raw.subarray(0, -2)).int(TAG.PAUSE) ?? 0
      this.opts.onSecurityDelay?.(pause / 100)
      await Bun.sleep(0) // let the UI breathe
    }

    const sw = raw.readUInt16BE(raw.length - 2)
    let data = raw.subarray(0, -2)
    if (encrypted && isSuccess(sw) && data.length >= 16) data = this.#decrypt(data)
    this.opts.onApdu?.('<', data, `SW ${sw.toString(16).toUpperCase()}`)
    return { sw, data, tlv: safeTlv(data) }
  }

  #decrypt(data: Buffer): Buffer {
    let plain: Buffer
    try {
      plain = aesDecrypt(this.#key!, data)
    } catch {
      throw new TangemError('Failed to decrypt card response (wrong access code?)', SW.INVALID_ACCESS_CODE)
    }
    const len = plain.readUInt16BE(0)
    const payload = plain.subarray(4)
    if (len !== payload.length || !crc16a(payload).equals(plain.subarray(2, 4))) {
      throw new TangemError('Corrupted encrypted response (length/CRC mismatch)')
    }
    return payload
  }

  async #openSession() {
    const mode = this.encryption
    let keyA: Buffer
    let secret: (keyB: Buffer) => Buffer
    if (mode === 'fast') {
      keyA = randomBytes(16)
      secret = keyB => Buffer.concat([keyA, keyB])
    } else {
      const kp = ecdhKeyPair()
      keyA = kp.publicKey
      secret = kp.sharedSecret
    }
    const res = await this.#exchange(INS.OPEN_SESSION, buildTlv([[TAG.SESSION_KEY_A, keyA]]), ENCRYPTION[mode])
    if (!isSuccess(res.sw)) throw TangemError.fromSw(res.sw, INS.OPEN_SESSION)
    const keyB = res.tlv.bytes(TAG.SESSION_KEY_B)
    this.uid = res.tlv.bytes(TAG.UID) ?? this.uid ?? this.conn.uid()
    if (!keyB || !this.uid) throw new TangemError('OPEN_SESSION: missing session key or UID')
    this.#key = sha256(Buffer.concat([secret(keyB), protocolKey(this.accessCode, this.uid)]))
  }
}

/** ISO 7816-4 command APDU, short Lc when possible, extended (00 hi lo) otherwise. */
export function frame(ins: number, p1: number, p2: number, data: Buffer): Buffer {
  const header = Buffer.from([0x00, ins, p1, p2])
  if (data.length === 0) return header
  const lc = data.length <= 0xff ? Buffer.from([data.length]) : Buffer.from([0x00, data.length >> 8, data.length & 0xff])
  return Buffer.concat([header, lc, data])
}

const u16 = (n: number) => Buffer.from([n >> 8, n & 0xff])
const insName = (ins: number) => Object.entries(INS).find(([, v]) => v === ins)?.[0] ?? `INS ${ins.toString(16)}`
function safeTlv(data: Buffer) {
  try { return new Tlv(data) } catch { return new Tlv([]) }
}
