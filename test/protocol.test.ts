import { describe, expect, test } from 'bun:test'
import {
  Tlv, buildTlv, crc16a, encodeDerivationPath, frame, luhn, parseCard, xrplAddress, Firmware, TAG,
} from '../src/index.ts'
import { aesDecrypt, aesEncrypt, protocolKey, sha256 } from '../src/crypto.ts'
import { dropsToUnits, parseNetworks } from '../src/networks.ts'

describe('crc16a (ISO 14443-3 CRC_A)', () => {
  test('reference vectors', () => {
    expect(crc16a(Buffer.from([0x00, 0x00])).toString('hex')).toBe('a01e')
    expect(crc16a(Buffer.from([0x12, 0x34])).toString('hex')).toBe('26cf')
  })
})

describe('TLV', () => {
  test('round trip incl. long form', () => {
    const big = Buffer.alloc(300, 7)
    const data = buildTlv([[0x01, Buffer.from('AB02000000055357', 'hex')], [0x02, null], [0x71, big]])
    expect(data.subarray(10, 14).toString('hex')).toBe('71ff012c')
    const tlv = new Tlv(data)
    expect(tlv.hex(0x01)).toBe('AB02000000055357')
    expect(tlv.has(0x02)).toBe(false)
    expect(tlv.bytes(0x71)?.length).toBe(300)
  })

  test('decodes a real legacy READ response', () => {
    // fw 1.x/2.x unencrypted card read from the original scribbles
    const raw = Buffer.from('0108AB020000000553570A0400000001050A736563703235366B31000701816501009000'.slice(0, -4), 'hex')
    const tlv = new Tlv(raw)
    expect(tlv.hex(TAG.CARD_ID)).toBe('AB02000000055357')
    expect(tlv.str(TAG.CURVE_ID)).toBe('secp256k1')
    expect(tlv.int(TAG.SETTINGS_MASK)).toBe(1)
  })
})

describe('card', () => {
  test('CID Luhn check', () => {
    expect(luhn('AB02000000055357')).toBe(true)
    expect(luhn('AB02000000055358')).toBe(false)
  })

  test('firmware parsing & comparison', () => {
    const fw = new Firmware('4.52r\0')
    expect([fw.major, fw.minor, fw.type]).toEqual([4, 52, 'release'])
    expect(fw.gte([4, 39])).toBe(true)
    expect(fw.gte([6, 21])).toBe(false)
    expect(new Firmware('6.33d SDK').type).toBe('sdk')
  })

  test('parseCard decodes settings & legacy wallet', () => {
    const tlv = buildTlv([
      [0x01, Buffer.from('AB02000000055357', 'hex')],
      [0x02, Buffer.from([2])],
      [0x80, Buffer.from('2.30r\0')],
      [0x0a, Buffer.from([0x00, 0x00, 0x30, 0x35])],
      [0x05, Buffer.from('secp256k1\0')],
      [0x07, Buffer.from([0x83])],
      [0x60, Buffer.from('04' + '11'.repeat(64), 'hex')],
      [0x62, Buffer.from([0, 0, 0, 10])],
    ])
    const card = parseCard(new Tlv(tlv), true)
    expect(card.status).toBe('loaded')
    expect(card.encryptionAllowed).toEqual(['none', 'fast', 'strong'])
    expect(card.settings).toContain('permanentWallet')
    expect(card.signingMethods).toEqual(['signHash', 'signRaw'])
    expect(card.wallets[0]?.remainingSignatures).toBe(10)
    expect(card.wallets[0]?.isPermanent).toBe(true)
  })
})

describe('apdu & crypto', () => {
  test('short and extended Lc', () => {
    expect(frame(0xf2, 0, 0, Buffer.alloc(3)).toString('hex')).toBe('00f2000003000000')
    expect(frame(0xf2, 0, 0, Buffer.alloc(256)).subarray(0, 7).toString('hex')).toBe('00f20000000100')
  })

  test('READ apdu matches the reverse engineered one', () => {
    const apdu = frame(0xf2, 0, 0, buildTlv([[0x10, sha256('000000')]]))
    expect(apdu.toString('hex').toUpperCase()).toBe('00F2000022102091B4D142823F7D20C5F08DF69122DE43F35F057A988D9619F6D3138485C9A203')
  })

  test('aes-256-cbc round trip / protocol key', () => {
    const key = sha256(Buffer.concat([Buffer.alloc(32, 1), protocolKey('000000', Buffer.from('028CC120', 'hex'))]))
    const plain = Buffer.from('hello tangem')
    expect(aesDecrypt(key, aesEncrypt(key, plain)).equals(plain)).toBe(true)
  })

  test('derivation path encoding', () => {
    expect(encodeDerivationPath("m/44'/144'/0'/0/0").toString('hex')).toBe('8000002c80000090800000000000000000000000')
    expect(() => encodeDerivationPath('m/x')).toThrow()
  })
})

describe('xrpl', () => {
  test('secp256k1 address (genesis account)', () => {
    expect(xrplAddress('0330E7FC9D56BB25D6893BA3F317AE5BCF33B3291BD63DB32654A313222F7FD020', 'secp256k1')).toBe('rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh')
  })

  test('uncompressed key compresses to the same address', () => {
    const { secp256k1 } = require('@noble/curves/secp256k1.js')
    const pub = secp256k1.Point.fromHex('0330E7FC9D56BB25D6893BA3F317AE5BCF33B3291BD63DB32654A313222F7FD020').toBytes(false)
    expect(xrplAddress(pub, 'secp256k1')).toBe('rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh')
  })

  test('ed25519 address', () => {
    // xrpl.js test vector: ED01FA53FA5A7E77798F882ECE20B1ABC00BB358A9E55A202D0D0676BD0CE37A63
    expect(xrplAddress('01FA53FA5A7E77798F882ECE20B1ABC00BB358A9E55A202D0D0676BD0CE37A63', 'ed25519')).toBe('rLUEXYuLiQptky37CqLcm9USQpPiz5rkpD')
  })
})

describe('networks', () => {
  test('drops & network list parsing', () => {
    expect(dropsToUnits('12500000')).toBe('12.5')
    expect(dropsToUnits('1')).toBe('0.000001')
    expect(parseNetworks('mainnet,xahau-testnet')).toEqual(['xrpl', 'xahau', 'xahau-testnet'])
    expect(() => parseNetworks('foo')).toThrow()
  })
})
