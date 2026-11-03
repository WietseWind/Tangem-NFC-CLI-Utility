import { describe, expect, test } from 'bun:test'
import { Session, Tangem, TangemError, Tlv, buildTlv, parseCard } from '../src/index.ts'
import type { CardConnection } from '../src/pcsc.ts'

/** Fake card: records APDUs, answers with a canned response. */
function fakeCard(response: Buffer) {
  const sent: Buffer[] = []
  const conn = {
    reader: 'fake',
    transmit: (apdu: Uint8Array) => { sent.push(Buffer.from(apdu)); return response },
    uid: () => Buffer.from('01020304', 'hex'),
    present: () => true,
    disconnect: () => {},
  } as unknown as CardConnection
  return { conn, sent }
}

function legacyCard(settingsMask: number, extra: Array<[number, Buffer]> = []) {
  return parseCard(new Tlv(buildTlv([
    [0x01, Buffer.from('AB02000000055357', 'hex')],
    [0x02, Buffer.from([1])], // empty
    [0x80, Buffer.from('2.30r\0')],
    [0x0a, Buffer.from([(settingsMask >> 8) & 0xff, settingsMask & 0xff])],
    [0x05, Buffer.from('secp256k1\0')],
    ...extra,
  ])), true)
}

function tangemWith(card: ReturnType<typeof legacyCard>, response: Buffer, session: { passcode?: string; cvc?: string } = {}) {
  const { conn, sent } = fakeCard(response)
  const t = new (Tangem as any)({ close() {} }, conn, new Session(conn, { encryption: 'none', ...session })) as Tangem
  t.card = card
  return { t, sent }
}

const OK_WALLET = Buffer.concat([buildTlv([[0x60, Buffer.from('03' + '11'.repeat(32), 'hex')]]), Buffer.from([0x90, 0x00])])
const ALLOW_UNENCRYPTED = 0x1000
const USE_CVC = 0x0040

describe('user codes', () => {
  test('custom passcode known from READ: nothing is sent with the default', async () => {
    const card = legacyCard(ALLOW_UNENCRYPTED)
    card.isPasscodeSet = true
    const { t, sent } = tangemWith(card, OK_WALLET)
    const err = await t.createWallet().catch(e => e)
    expect(err).toBeInstanceOf(TangemError)
    expect(err.needs).toEqual(['passcode'])
    expect(sent.length).toBe(0)
  })

  test('UseCVC card: asks for the CVC up front, then sends it as 3 bytes', async () => {
    const card = legacyCard(ALLOW_UNENCRYPTED | USE_CVC)
    const { t, sent } = tangemWith(card, OK_WALLET)
    const err = await t.createWallet().catch(e => e)
    expect(err.needs).toEqual(['cvc'])
    expect(sent.length).toBe(0)

    t.session.cvc = '123'
    const wallet = await t.createWallet()
    expect(wallet.publicKey).toBe('03' + '11'.repeat(32))
    expect(sent[0]!.toString('hex')).toContain('1903313233') // tag 0x19, len 3, "123"
  })

  test('wrong-code answer from the card lists the codes to ask for', async () => {
    const card = legacyCard(ALLOW_UNENCRYPTED | USE_CVC)
    const { t } = tangemWith(card, Buffer.from([0x6a, 0x86]), { cvc: '999' })
    const err = await t.createWallet().catch(e => e)
    expect(err.needs).toEqual(['passcode', 'cvc'])
  })
})

describe('card fields', () => {
  test('terminal link, default wallet index, max signatures', () => {
    const card = legacyCard(ALLOW_UNENCRYPTED, [
      [0x5f, Buffer.from([1])],
      [0x65, Buffer.from([0])],
      [0x08, Buffer.from([0x00, 0x0f, 0x42, 0x40])],
    ])
    expect(card.terminalLink).toBe('linkedToAnother')
    expect(card.defaultWalletIndex).toBe(0)
    expect(card.maxSignatures).toBe(1_000_000)
  })
})
