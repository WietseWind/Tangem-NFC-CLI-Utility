/** Tangem SimpleTLV: 1-byte tag, 1-byte length (or 0xFF + uint16 BE), value. */

export type TlvValue = Uint8Array | string | number | null | undefined

export interface TlvEntry {
  tag: number
  value: Buffer
}

export function encodeTlv(tag: number, value: Uint8Array): Buffer {
  const len = value.length
  const header = len > 0xfe ? Buffer.from([tag, 0xff, len >> 8, len & 0xff]) : Buffer.from([tag, len])
  return Buffer.concat([header, value])
}

/** Build a TLV payload from [tag, value] pairs; null/undefined values are skipped. */
export function buildTlv(entries: Array<[number, Uint8Array | null | undefined]>): Buffer {
  return Buffer.concat(entries.filter(([, v]) => v != null).map(([t, v]) => encodeTlv(t, v!)))
}

export function decodeTlv(data: Uint8Array): TlvEntry[] {
  const buf = Buffer.from(data.buffer, data.byteOffset, data.byteLength)
  const out: TlvEntry[] = []
  let i = 0
  while (i + 2 <= buf.length) {
    const tag = buf[i++]!
    let len = buf[i++]!
    if (len === 0xff) {
      if (i + 2 > buf.length) break
      len = buf.readUInt16BE(i)
      i += 2
    }
    if (i + len > buf.length) throw new Error(`Malformed TLV: tag 0x${tag.toString(16)} wants ${len} bytes, ${buf.length - i} left`)
    out.push({ tag, value: buf.subarray(i, i + len) })
    i += len
  }
  return out
}

/** Convenience accessor over decoded TLV entries. */
export class Tlv {
  readonly entries: TlvEntry[]
  constructor(data: Uint8Array | TlvEntry[]) {
    this.entries = Array.isArray(data) ? data : decodeTlv(data)
  }
  has(tag: number) { return this.entries.some(e => e.tag === tag) }
  bytes(tag: number) { return this.entries.find(e => e.tag === tag)?.value }
  all(tag: number) { return this.entries.filter(e => e.tag === tag).map(e => e.value) }
  hex(tag: number) { return this.bytes(tag)?.toString('hex').toUpperCase() }
  /** UTF-8 string, trailing NULs stripped. */
  str(tag: number) {
    const v = this.bytes(tag)
    return v ? v.toString('utf8').replace(/\0+$/, '') : undefined
  }
  /** Big-endian unsigned integer of any length (≤ 6 bytes). */
  int(tag: number) {
    const v = this.bytes(tag)
    return v && v.length > 0 ? v.reduce((n, b) => n * 256 + b, 0) : undefined
  }
  nested(tag: number) {
    const v = this.bytes(tag)
    return v ? new Tlv(v) : undefined
  }
}

export const hex = (s: string) => Buffer.from(s.replace(/\s+/g, ''), 'hex')
export const u8 = (n: number) => Buffer.from([n & 0xff])
export const u16 = (n: number) => Buffer.from([(n >> 8) & 0xff, n & 0xff])
export const u32 = (n: number) => { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0); return b }
export const cstring = (s: string) => Buffer.from(s + '\0', 'utf8')
