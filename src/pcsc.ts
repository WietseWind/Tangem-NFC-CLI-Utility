/**
 * Minimal PC/SC binding via bun:ffi — talks straight to the OS smart card stack:
 *   macOS   /System/Library/Frameworks/PCSC.framework
 *   Linux   libpcsclite (pcscd)
 *   Windows winscard.dll
 * No native addon, nothing to compile.
 */
import { dlopen, FFIType } from 'bun:ffi'

const SCARD_SCOPE_SYSTEM = 2
const SCARD_SHARE_SHARED = 2
const SCARD_PROTOCOL_T0 = 1
const SCARD_PROTOCOL_T1 = 2
const SCARD_LEAVE_CARD = 0
const SCARD_RESET_CARD = 1

export const SCARD = {
  E_INSUFFICIENT_BUFFER: 0x80100008,
  E_UNKNOWN_READER: 0x80100009,
  E_TIMEOUT: 0x8010000a,
  E_SHARING_VIOLATION: 0x8010000b,
  E_NO_SMARTCARD: 0x8010000c,
  E_PROTO_MISMATCH: 0x8010000f,
  E_NOT_TRANSACTED: 0x80100016,
  E_READER_UNAVAILABLE: 0x80100017,
  E_NO_SERVICE: 0x8010001d,
  E_SERVICE_STOPPED: 0x8010001e,
  E_NO_READERS_AVAILABLE: 0x8010002e,
  W_UNRESPONSIVE_CARD: 0x80100066,
  W_UNPOWERED_CARD: 0x80100067,
  W_RESET_CARD: 0x80100068,
  W_REMOVED_CARD: 0x80100069,
} as const

/** Return codes meaning "no (usable) card in this reader right now". */
const NO_CARD = new Set<number>([
  SCARD.E_NO_SMARTCARD, SCARD.W_REMOVED_CARD, SCARD.W_UNRESPONSIVE_CARD, SCARD.W_UNPOWERED_CARD,
  SCARD.E_PROTO_MISMATCH, SCARD.E_READER_UNAVAILABLE, SCARD.E_SHARING_VIOLATION, SCARD.E_TIMEOUT,
  SCARD.E_UNKNOWN_READER, SCARD.W_RESET_CARD,
])

export class PcscError extends Error {
  constructor(readonly fn: string, readonly code: number) {
    super(`${fn} failed: ${describe(code)}`)
    this.name = 'PcscError'
  }
  get noCard() { return NO_CARD.has(this.code) }
}

function describe(code: number): string {
  const name = Object.entries(SCARD).find(([, v]) => v === code)?.[0]
  const hint = code === SCARD.E_NO_SERVICE ? ' (is the PC/SC service running? Linux: `sudo systemctl start pcscd`)'
    : code === SCARD.E_NO_READERS_AVAILABLE ? ' (no reader connected)'
    : code === SCARD.E_NOT_TRANSACTED ? ' (reader may not support extended-length APDUs, see README › Reader compatibility)'
    : ''
  return `${name ? `SCARD_${name}` : 'error'} 0x${code.toString(16).padStart(8, '0')}${hint}`
}

// Platform ABI: DWORD/LONG are 32 bit on macOS & Windows, `unsigned long`/`long` (64 bit) on Linux.
// SCARDCONTEXT/SCARDHANDLE: int32 on macOS, long on Linux, ULONG_PTR on Windows.
const os = process.platform
const LIB = os === 'darwin' ? ['/System/Library/Frameworks/PCSC.framework/PCSC']
  : os === 'win32' ? ['winscard.dll']
  : ['libpcsclite.so.1', 'libpcsclite.so']
const WIDE_DWORD = os !== 'darwin' && os !== 'win32'
const WIDE_HANDLE = os !== 'darwin'
const A = os === 'win32' ? 'A' : '' // ANSI variants on Windows

const H = WIDE_HANDLE ? FFIType.i64 : FFIType.i32
const DW = WIDE_DWORD ? FFIType.u64 : FFIType.u32
const RET = WIDE_DWORD ? FFIType.i64 : FFIType.i32
const P = FFIType.ptr

const symbols = {
  SCardEstablishContext: { args: [DW, P, P, P], returns: RET },
  SCardReleaseContext: { args: [H], returns: RET },
  [`SCardListReaders${A}`]: { args: [H, P, P, P], returns: RET },
  [`SCardConnect${A}`]: { args: [H, P, DW, DW, P, P], returns: RET },
  SCardDisconnect: { args: [H, DW], returns: RET },
  SCardTransmit: { args: [H, P, P, DW, P, P, P], returns: RET },
  [`SCardStatus${A}`]: { args: [H, P, P, P, P, P, P], returns: RET },
} as const

type Lib = ReturnType<typeof dlopen<typeof symbols>>['symbols']
let lib: Lib | undefined

function load(): Lib {
  if (lib) return lib
  let lastError: unknown
  for (const path of LIB) {
    try { return (lib = dlopen(path, symbols).symbols) } catch (e) { lastError = e }
  }
  throw new Error(`Could not load the PC/SC library (${LIB.join(', ')})${os === 'linux' ? ' — install pcscd + libpcsclite' : ''}: ${lastError}`)
}

const code = (rv: number | bigint) => Number(BigInt.asUintN(32, BigInt(rv)))
const check = (fn: string, rv: number | bigint) => {
  const c = code(rv)
  if (c !== 0) throw new PcscError(fn, c)
}

// Out-parameter cells sized for the platform ABI
const handleCell = () => (WIDE_HANDLE ? new BigInt64Array(1) : new Int32Array(1))
const dwordCell = (v = 0) => (WIDE_DWORD ? new BigUint64Array([BigInt(v)]) : new Uint32Array([v]))
const dw = (v: number) => (WIDE_DWORD ? BigInt(v) : v)

function ioRequest(protocol: number) {
  // SCARD_IO_REQUEST { DWORD dwProtocol; DWORD cbPciLength; }
  return WIDE_DWORD ? new BigUint64Array([BigInt(protocol), 16n]) : new Uint32Array([protocol, 8])
}

const cstr = (s: string) => Buffer.from(s + '\0', 'utf8')

export class Pcsc {
  #ctx: number | bigint
  #closed = false

  private constructor(ctx: number | bigint) { this.#ctx = ctx }

  static open(): Pcsc {
    const s = load()
    const ctx = handleCell()
    check('SCardEstablishContext', s.SCardEstablishContext(dw(SCARD_SCOPE_SYSTEM), null, null, ctx))
    return new Pcsc(ctx[0]!)
  }

  listReaders(): string[] {
    const s = load()
    const list = s[`SCardListReaders${A}`]!
    const len = dwordCell()
    let rv = code(list(this.#ctx, null, null, len))
    if (rv === SCARD.E_NO_READERS_AVAILABLE) return []
    check('SCardListReaders', rv)
    const buf = Buffer.alloc(Number(len[0]))
    rv = code(list(this.#ctx, null, buf, len))
    if (rv === SCARD.E_NO_READERS_AVAILABLE) return []
    check('SCardListReaders', rv)
    return buf.subarray(0, Number(len[0])).toString('utf8').split('\0').filter(Boolean)
  }

  /** Connect to the card in `reader`. Throws PcscError (`.noCard === true` when the reader is empty). */
  connect(reader: string): CardConnection {
    const s = load()
    const handle = handleCell()
    const proto = dwordCell()
    check('SCardConnect', s[`SCardConnect${A}`]!(
      this.#ctx, cstr(reader), dw(SCARD_SHARE_SHARED), dw(SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1), handle, proto,
    ))
    return new CardConnection(reader, handle[0]!, Number(proto[0]))
  }

  /**
   * Poll all (matching) readers until a card shows up.
   * `reader` filters by index or case-insensitive name substring.
   */
  async waitForCard(opts: { reader?: string; timeoutMs?: number; signal?: AbortSignal; intervalMs?: number } = {}): Promise<CardConnection> {
    const started = Date.now()
    const interval = opts.intervalMs ?? 250
    while (true) {
      if (opts.signal?.aborted) throw new Error('Aborted')
      for (const reader of this.matchReaders(opts.reader)) {
        try {
          return this.connect(reader)
        } catch (e) {
          if (!(e instanceof PcscError && e.noCard)) throw e
        }
      }
      if (opts.timeoutMs && Date.now() - started > opts.timeoutMs) throw new Error('Timed out waiting for a card')
      await Bun.sleep(interval)
    }
  }

  /** Resolve once `reader` no longer has a card. */
  async waitForRemoval(reader: string, intervalMs = 250): Promise<void> {
    while (true) {
      try {
        this.connect(reader).disconnect()
      } catch (e) {
        if (e instanceof PcscError && e.noCard) return
        throw e
      }
      await Bun.sleep(intervalMs)
    }
  }

  matchReaders(filter?: string): string[] {
    const readers = this.listReaders()
    if (filter === undefined || filter === '') return readers
    if (/^\d+$/.test(filter)) return readers[Number(filter)] ? [readers[Number(filter)]!] : []
    return readers.filter(r => r.toLowerCase().includes(filter.toLowerCase()))
  }

  close() {
    if (this.#closed) return
    this.#closed = true
    load().SCardReleaseContext(this.#ctx)
  }
}

export class CardConnection {
  #handle: number | bigint
  #connected = true
  readonly #pci: BigUint64Array | Uint32Array

  constructor(readonly reader: string, handle: number | bigint, readonly protocol: number) {
    this.#handle = handle
    this.#pci = ioRequest(protocol)
  }

  /** Send a raw APDU, returns the full response including SW1 SW2. */
  transmit(apdu: Uint8Array, maxResponse = 0x10000 + 2): Buffer {
    if (!this.#connected) throw new Error('Card connection closed')
    const out = Buffer.alloc(maxResponse)
    const outLen = dwordCell(maxResponse)
    check('SCardTransmit', load().SCardTransmit(this.#handle, this.#pci, apdu, dw(apdu.length), null, out, outLen))
    return Buffer.from(out.subarray(0, Number(outLen[0])))
  }

  /** Is the card still there? Local SCardStatus query, nothing is sent to the card. */
  present(): boolean {
    if (!this.#connected) return false
    const name = Buffer.alloc(512)
    const nameLen = dwordCell(name.length)
    const atr = Buffer.alloc(64)
    const atrLen = dwordCell(atr.length)
    const rv = code(load()[`SCardStatus${A}`]!(this.#handle, name, nameLen, dwordCell(), dwordCell(), atr, atrLen))
    if (rv === 0) return true
    if (NO_CARD.has(rv)) return false
    throw new PcscError('SCardStatus', rv)
  }

  /** ISO 14443-3 UID through the reader's GET DATA pseudo-APDU (FF CA 00 00 00), if supported. */
  uid(): Buffer | undefined {
    try {
      const r = this.transmit(Buffer.from([0xff, 0xca, 0x00, 0x00, 0x00]))
      return r.length > 2 && r[r.length - 2] === 0x90 && r[r.length - 1] === 0x00 ? r.subarray(0, -2) : undefined
    } catch {
      return undefined
    }
  }

  disconnect(reset = false) {
    if (!this.#connected) return
    this.#connected = false
    load().SCardDisconnect(this.#handle, dw(reset ? SCARD_RESET_CARD : SCARD_LEAVE_CARD))
  }
}
