import { compressPublicKey, ripemd160, sha256 } from './crypto.ts'

const ALPHABET = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz'

function base58(data: Uint8Array): string {
  let n = BigInt('0x' + (Buffer.from(data).toString('hex') || '0'))
  let out = ''
  while (n > 0n) {
    out = ALPHABET[Number(n % 58n)] + out
    n /= 58n
  }
  for (const b of data) {
    if (b !== 0) break
    out = ALPHABET[0] + out
  }
  return out
}

const base58check = (payload: Uint8Array) =>
  base58(Buffer.concat([payload, sha256(sha256(payload)).subarray(0, 4)]))

/** Curves that map to an XRPL account (secp256k1 and ed25519 keys). */
export const xrplCurve = (curve?: string) =>
  curve === 'secp256k1' ? 'secp256k1' : curve === 'ed25519' || curve === 'ed25519_slip0010' ? 'ed25519' : undefined

/** XRPL-formatted public key: 33-byte compressed secp256k1, or 0xED + 32-byte ed25519. */
export function xrplPublicKey(publicKey: Uint8Array | string, curve: string): Buffer {
  const key = typeof publicKey === 'string' ? Buffer.from(publicKey, 'hex') : Buffer.from(publicKey)
  if (xrplCurve(curve) === 'ed25519') {
    if (key.length === 33 && key[0] === 0xed) return key
    if (key.length !== 32) throw new Error(`Invalid ed25519 public key length ${key.length}`)
    return Buffer.concat([Buffer.from([0xed]), key])
  }
  if (xrplCurve(curve) === 'secp256k1') {
    const c = compressPublicKey(key)
    if (c.length !== 33) throw new Error(`Invalid secp256k1 public key length ${key.length}`)
    return c
  }
  throw new Error(`Curve ${curve} has no XRPL address`)
}

/** Classic r-address for a public key. */
export function xrplAddress(publicKey: Uint8Array | string, curve: string): string {
  const accountId = ripemd160(sha256(xrplPublicKey(publicKey, curve)))
  return base58check(Buffer.concat([Buffer.from([0x00]), accountId]))
}
