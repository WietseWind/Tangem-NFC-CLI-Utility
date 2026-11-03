#!/usr/bin/env bun
import { parseArgs } from 'node:util'
import * as p from '@clack/prompts'
import pc from 'picocolors'
import pkg from '../../package.json' with { type: 'json' }
import { Tangem } from '../tangem.ts'
import { TangemError } from '../session.ts'
import { PcscError } from '../pcsc.ts'
import { formatCardId, type CardInfo, type Wallet } from '../card.ts'
import { xrplAddress, xrplCurve, xrplPublicKey } from '../xrpl.ts'
import { CURVES, FW, SW, XRPL_DERIVATION_PATH, type Curve, type EncryptionMode } from '../constants.ts'
import { NETWORK_IDS, checkAccount, parseNetworks, type NetworkId } from '../networks.ts'
import { renderCard, renderNetwork, renderWallet, type WalletView, type XrplAccount } from './render.ts'

const HELP = `
${pc.bold('tangem')} ${pc.dim(`v${pkg.version}`)} — Tangem NFC cards over a USB PC/SC reader

${pc.bold('Usage')}
  tangem                     interactive wizard
  tangem <command> [options]

${pc.bold('Commands')}
  info                       read the card: firmware, curves, settings, wallets, XRPL addresses
  create                     create a wallet (key pair) on the card
  delete                     delete (purge) a wallet — irreversible
  address                    show XRPL address(es) of the card's wallets
  readers                    list PC/SC readers

${pc.bold('Options')}
  -r, --reader <name|index>  reader to use (default: first reader with a card)
  -a, --access-code <code>   access code / PIN1 (default 000000; prompted if wrong)
  -p, --passcode <code>      passcode / PIN2 (default 000; prompted if wrong)
      --cvc <code>           CVC for cards that require it
  -e, --encryption <mode>    auto | none | fast | strong (default auto)
  -c, --curve <curve>        create: ${CURVES.join(', ')}
  -i, --index <n>            wallet index (create / delete / address)
      --path <path>          HD derivation path for XRPL (default ${XRPL_DERIVATION_PATH})
      --check                look up the XRPL address(es) on all networks
  -n, --networks <list>      networks to check (implies --check): all, mainnet, testnet,
                             ${NETWORK_IDS.join(', ')}
  -y, --yes                  don't ask for confirmation (delete)
      --force                delete: skip the permanent-wallet check, let the card decide
      --json                 machine readable output (no prompts)
      --no-input             never prompt; fail on missing input
  -t, --timeout <seconds>    give up waiting for a card
  -v, --verbose              print APDUs (plain text, incl. PIN hashes) to stderr
  -h, --help                 this help
      --version              print version
`

interface Opts {
  reader?: string
  accessCode?: string
  passcode?: string
  cvc?: string
  encryption: EncryptionMode | 'auto'
  curve?: Curve
  index?: number
  path: string
  /** Networks to look addresses up on (empty = no lookups) */
  networks: NetworkId[]
  yes: boolean
  force: boolean
  json: boolean
  interactive: boolean
  timeoutMs?: number
  verbose: boolean
}

class Cancelled extends Error {}

async function main() {
  const { values: v, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      reader: { type: 'string', short: 'r' },
      'access-code': { type: 'string', short: 'a' },
      passcode: { type: 'string', short: 'p' },
      cvc: { type: 'string' },
      encryption: { type: 'string', short: 'e', default: 'auto' },
      curve: { type: 'string', short: 'c' },
      index: { type: 'string', short: 'i' },
      path: { type: 'string', default: XRPL_DERIVATION_PATH },
      check: { type: 'boolean', default: false },
      networks: { type: 'string', short: 'n' },
      yes: { type: 'boolean', short: 'y', default: false },
      force: { type: 'boolean', default: false },
      json: { type: 'boolean', default: false },
      'no-input': { type: 'boolean', default: false },
      timeout: { type: 'string', short: 't' },
      verbose: { type: 'boolean', short: 'v', default: false },
      help: { type: 'boolean', short: 'h', default: false },
      version: { type: 'boolean', default: false },
    },
  })

  if (v.help || positionals[0] === 'help') return void console.log(HELP)
  if (v.version) return void console.log(pkg.version)

  if (!['auto', 'none', 'fast', 'strong'].includes(v.encryption!)) throw new Error(`--encryption must be auto, none, fast or strong`)
  if (v.curve && !(CURVES as readonly string[]).includes(v.curve)) throw new Error(`Unknown curve "${v.curve}". Options: ${CURVES.join(', ')}`)
  if (v.index !== undefined && !/^\d+$/.test(v.index)) throw new Error('--index must be a number')
  if (v.timeout !== undefined && !(Number(v.timeout) > 0)) throw new Error('--timeout must be a positive number of seconds')

  const opts: Opts = {
    reader: v.reader,
    accessCode: v['access-code'],
    passcode: v.passcode,
    cvc: v.cvc,
    encryption: v.encryption as Opts['encryption'],
    curve: v.curve as Curve | undefined,
    index: v.index !== undefined ? Number(v.index) : undefined,
    path: v.path!,
    networks: v.networks ? parseNetworks(v.networks) : v.check ? NETWORK_IDS : [],
    yes: v.yes!,
    force: v.force!,
    json: v.json!,
    interactive: !!process.stdin.isTTY && !!process.stdout.isTTY && !v.json && !v['no-input'],
    timeoutMs: v.timeout ? Number(v.timeout) * 1000 : undefined,
    verbose: v.verbose!,
  }

  const command = positionals[0]
  switch (command) {
    case undefined: return opts.interactive ? wizard(opts) : info(opts)
    case 'info': case 'scan': case 'read': return info(opts)
    case 'create': case 'generate': return create(opts)
    case 'delete': case 'purge': return remove(opts)
    case 'address': case 'xrpl': return address(opts)
    case 'readers': return readers(opts)
    default: throw new Error(`Unknown command "${command}" — see tangem --help`)
  }
}

// ── commands ────────────────────────────────────────────────────────────────

async function info(opts: Opts) {
  await withCard(opts, async (tangem, card) => {
    const views = await walletViews(tangem, card, opts)
    output(opts, { ...card, wallets: views }, () => renderCard(card, views))
  })
}

async function create(opts: Opts) {
  await withCard(opts, async (tangem, card) => {
    const wallet = await doCreate(tangem, card, opts)
    const [view] = await walletViews(tangem, card, opts, [wallet])
    output(opts, { cardId: card.cardId, wallet: view }, () => `\n  ${pc.green('Wallet created')}\n${renderWallet(view!)}`)
  })
}

async function remove(opts: Opts) {
  await withCard(opts, async (tangem, card) => {
    const index = await doDelete(tangem, card, opts)
    if (index === undefined) return
    output(opts, { cardId: card.cardId, deleted: index }, () => `\n  ${pc.green(`Wallet #${index} deleted`)}\n`)
  })
}

async function address(opts: Opts) {
  await withCard(opts, async (tangem, card) => {
    const wallets = card.wallets.filter(w => opts.index === undefined || w.index === opts.index)
    if (wallets.length === 0) throw new Error(opts.index === undefined ? 'No wallets on this card' : `No wallet at index ${opts.index}`)
    const views = await walletViews(tangem, card, opts, wallets)
    output(opts, { cardId: card.cardId, wallets: views.map(w => ({ index: w.index, curve: w.curve, xrpl: w.xrpl })) }, () =>
      views.map(w => w.xrpl.length
        ? w.xrpl.map(a => `${pc.dim(`#${w.index}${a.path ? ` ${a.path}` : ''}`)}  ${a.address}` +
          (a.networks ?? []).map(n => `\n    ${renderNetwork(n)}`).join('')).join('\n')
        : pc.dim(`#${w.index}  (${w.curve}: no XRPL address)`)).join('\n'))
  })
}

async function readers(opts: Opts) {
  const list = Tangem.listReaders()
  output(opts, { readers: list }, () => list.length
    ? list.map((r, i) => `  ${pc.dim(String(i))}  ${r}`).join('\n')
    : pc.yellow('No PC/SC readers found'))
}

async function wizard(opts: Opts) {
  p.intro(pc.bgCyan(pc.black(' tangem ')))
  while (true) {
    const { tangem, card: scanned } = await openCard(opts)
    let card = scanned
    // next: scan another card after this one is removed; removed: it's already gone
    let next: 'next' | 'removed' | 'quit' | undefined
    try {
      console.log(renderCard(card, await walletViews(tangem, card, opts)))
      while (!next) {
        const free = tangem.freeWalletIndex()
        const actions: Array<{ value: string; label: string; hint?: string }> = [{ value: 'next', label: 'Scan another card', hint: 'or just swap cards' }]
        if (card.wallets.some(w => xrplCurve(w.curve))) actions.push({ value: 'check', label: 'Check XRPL / Xahau networks', hint: 'mainnet + testnet' })
        actions.push({ value: 'refresh', label: 'Re-read card' }, { value: 'quit', label: 'Quit' })
        if (!tangem.createBlocker()) actions.push({ value: 'create', label: 'Create wallet', hint: card.maxWallets > 1 ? `slot #${free}` : undefined })
        if (card.wallets.some(w => !tangem.purgeBlocker(w.index, opts.force))) actions.push({ value: 'delete', label: 'Delete wallet', hint: 'irreversible' })
        if (card.wallets.some(w => w.chainCode && w.curve === 'secp256k1')) actions.push({ value: 'derive', label: 'Derive XRPL address at custom path' })
        const action = await menu(tangem, actions)
        if (action === 'removed') {
          p.log.info('Card removed')
          next = 'removed'
          continue
        }
        try {
          if (action === 'create') {
            const wallet = await doCreate(tangem, card, opts)
            console.log(`\n  ${pc.green('Wallet created')}\n${renderWallet((await walletViews(tangem, card, opts, [wallet]))[0]!)}`)
          } else if (action === 'delete') {
            const index = await doDelete(tangem, card, opts)
            if (index !== undefined) p.log.success(`Wallet #${index} deleted`)
          } else if (action === 'check') {
            const networks = opts.networks.length ? opts.networks : NETWORK_IDS
            console.log((await walletViews(tangem, card, { ...opts, networks })).map(renderWallet).join(''))
          } else if (action === 'derive') {
            const path = await ask(p.text({ message: 'Derivation path', initialValue: opts.path, validate: s => (s && /^m(\/\d+['hH]?)+$/.test(s.trim()) ? undefined : "e.g. m/44'/144'/0'/0/0") }))
            const views = await walletViews(tangem, card, { ...opts, path: path.trim() })
            console.log(views.map(renderWallet).join(''))
          } else if (action === 'refresh') {
            card = await scan(tangem, opts)
            console.log(renderCard(card, await walletViews(tangem, card, opts)))
          } else {
            next = action as 'next' | 'quit'
          }
        } catch (e) {
          if (e instanceof Cancelled) continue
          if (e instanceof PcscError && e.noCard) {
            p.log.warn('Card was removed')
            next = 'removed'
            continue
          }
          p.log.error(errorMessage(e))
        }
      }
      if (next === 'next') {
        const s = status(opts)
        s.start('Remove the card…')
        await tangem.waitForRemoval()
        s.stop('Card removed')
      }
    } finally {
      tangem.close()
    }
    if (next === 'quit') return p.outro('Bye')
  }
}

/** The wizard menu; resolves to 'removed' as soon as the card leaves the reader. */
async function menu(tangem: Tangem, options: Array<{ value: string; label: string; hint?: string }>): Promise<string> {
  const removed = new AbortController()
  const watch = setInterval(() => {
    try {
      if (!tangem.conn.present()) removed.abort()
    } catch {
      removed.abort()
    }
  }, 300)
  try {
    const choice = await p.select({ message: 'What next?', options, initialValue: 'next', signal: removed.signal })
    if (removed.signal.aborted) return 'removed'
    if (p.isCancel(choice)) throw new Cancelled()
    return choice
  } finally {
    clearInterval(watch)
  }
}

// ── flows ───────────────────────────────────────────────────────────────────

const CURVE_HINT: Record<string, string> = {
  secp256k1: 'XRPL, Bitcoin, Ethereum',
  ed25519: 'XRPL (Ed25519), Solana, Cardano',
  ed25519_slip0010: 'Ed25519 with SLIP-0010 HD derivation',
  secp256r1: 'NIST P-256',
  bip0340: 'Schnorr / Taproot',
  bls12381_G2: 'BLS',
  bls12381_G2_AUG: 'BLS (aug)',
  bls12381_G2_POP: 'BLS (proof of possession, ETH2)',
}

async function doCreate(tangem: Tangem, card: CardInfo, opts: Opts): Promise<Wallet> {
  const blocker = tangem.createBlocker()
  if (blocker) throw new Error(blocker)

  let curve = opts.curve
  if (!card.firmware.gte(FW.multiwallet)) {
    if (curve && curve !== card.defaultCurve) throw new Error(`This card can only create ${card.defaultCurve} wallets`)
    curve = card.defaultCurve as Curve
  } else if (!curve) {
    curve = opts.interactive
      ? await ask(p.select({
        message: 'Curve',
        initialValue: 'secp256k1' as Curve,
        options: card.supportedCurves.map(c => ({ value: c, label: c, hint: CURVE_HINT[c] })),
      }))
      : 'secp256k1'
  }
  const curveBlocker = tangem.createBlocker(curve)
  if (curveBlocker) throw new Error(curveBlocker)

  return withPasscode(tangem, opts, 'Creating wallet…', () => tangem.createWallet({ curve, index: opts.index, cvc: opts.cvc }))
}

/** Returns the deleted index, or undefined when the user backed out. */
async function doDelete(tangem: Tangem, card: CardInfo, opts: Opts): Promise<number | undefined> {
  if (card.wallets.length === 0) throw new Error('No wallets on this card')
  let index = opts.index
  if (index === undefined) {
    if (card.wallets.length === 1) index = card.wallets[0]!.index
    else if (opts.interactive) {
      index = await ask(p.select({
        message: 'Wallet to delete',
        options: card.wallets.map(w => ({
          value: w.index,
          label: `#${w.index} ${w.curve} ${walletLabel(w)}`,
          hint: tangem.purgeBlocker(w.index, opts.force),
          disabled: !!tangem.purgeBlocker(w.index, opts.force),
        })),
      }))
    } else throw new Error('This card has several wallets — pass --index')
  }
  const blocker = tangem.purgeBlocker(index, opts.force)
  if (blocker) throw new Error(blocker)

  const wallet = card.wallets.find(w => w.index === index)!
  if (!opts.yes) {
    if (!opts.interactive) throw new Error('Refusing to delete a wallet without confirmation — pass --yes')
    p.log.warn(`${pc.red('This destroys the private key of wallet')} #${index} ${walletLabel(wallet)}\n${pc.red('Any funds still on it are lost forever.')}`)
    const ok = await ask(p.confirm({ message: `Delete wallet #${index}?`, initialValue: false }))
    if (!ok) {
      p.log.info('Kept the wallet')
      return undefined
    }
  }
  await withPasscode(tangem, opts, 'Deleting wallet…', () => tangem.purgeWallet(index, { force: opts.force }))
  return index
}

const walletLabel = (w: Wallet) => {
  const curve = xrplCurve(w.curve)
  return curve ? xrplAddress(w.publicKey, curve) : `${w.publicKey.slice(0, 16)}…`
}

async function walletViews(tangem: Tangem, card: CardInfo, opts: Opts, wallets = card.wallets): Promise<WalletView[]> {
  const views: WalletView[] = []
  for (const w of wallets) {
    const xrpl: XrplAccount[] = []
    const curve = xrplCurve(w.curve)
    if (curve && w.publicKey) xrpl.push({ address: xrplAddress(w.publicKey, curve), publicKey: xrplPublicKey(w.publicKey, curve).toString('hex').toUpperCase() })
    // HD wallets: Tangem apps use the BIP44 XRP path — derive it on the card.
    if (w.chainCode && w.curve === 'secp256k1' && card.firmware.gte(FW.hdWallet)) {
      try {
        const derived = await tangem.readWallet(w.index, opts.path)
        xrpl.push({ path: opts.path, address: xrplAddress(derived.publicKey, 'secp256k1'), publicKey: xrplPublicKey(derived.publicKey, 'secp256k1').toString('hex').toUpperCase() })
      } catch (e) {
        if (opts.verbose) console.error(pc.dim(`derivation failed: ${errorMessage(e)}`))
      }
    }
    views.push({ ...w, xrpl })
  }
  if (opts.networks.length) {
    const s = status(opts)
    s.start(`Checking ${opts.networks.length} network(s)…`)
    await Promise.all(views.flatMap(w => w.xrpl).map(async a => { a.networks = await checkAccount(a.address, opts.networks) }))
    s.stop('Network lookups done')
  }
  return views
}

// ── plumbing ────────────────────────────────────────────────────────────────

interface Status { start(m: string): void; message(m: string): void; stop(m?: string): void; error(m?: string): void }

function status(opts: Opts): Status {
  // clack's spinner swallows SIGINT; make Ctrl+C (e.g. while waiting for a card) exit
  if (opts.interactive) return p.spinner({ onCancel: () => process.exit(130) })
  const say = (m?: string) => !opts.json && m && console.error(pc.dim(m))
  return { start: say, message: () => {}, stop: () => {}, error: () => {} }
}

async function openCard(opts: Opts): Promise<{ tangem: Tangem; card: CardInfo }> {
  const s = status(opts)
  s.start(opts.reader ? `Place a Tangem card on reader "${opts.reader}"…` : 'Place a Tangem card on the reader…')
  let tangem: Tangem | undefined
  try {
    tangem = await Tangem.connect({
      reader: opts.reader,
      timeoutMs: opts.timeoutMs,
      accessCode: opts.accessCode,
      passcode: opts.passcode,
      encryption: opts.encryption,
      onApdu: opts.verbose ? (dir, data, note) => console.error(pc.dim(`${dir} ${note ?? ''} ${data.toString('hex').toUpperCase()}`)) : undefined,
      onSecurityDelay: secs => s.message(`Security delay — keep the card on the reader (${Math.ceil(secs)}s)`),
    })
    s.message('Reading card…')
    const card = await scan(tangem, opts, s)
    s.stop(`Card ${formatCardId(card.cardId)} ${pc.dim(`on ${tangem.conn.reader}`)}`)
    return { tangem, card }
  } catch (e) {
    s.error(errorMessage(e))
    tangem?.close()
    throw e instanceof TangemError || e instanceof PcscError ? new Reported(errorMessage(e)) : e
  }
}

/** scan(), prompting for the access code when the card rejects the current one. */
async function scan(tangem: Tangem, opts: Opts, s: Status = status(opts)): Promise<CardInfo> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await tangem.scan()
    } catch (e) {
      if (!(e instanceof TangemError && e.sw === SW.INVALID_ACCESS_CODE) || !opts.interactive || attempt > 3) throw e
      s.stop(pc.yellow(attempt === 1 ? 'This card has a custom access code' : 'Wrong access code'))
      tangem.session.setAccessCode(await ask(p.password({ message: 'Access code (PIN1)', validate: v => (v ? undefined : 'Required') })))
      s.start('Reading card…')
    }
  }
}

/** Run a PIN2-protected command, prompting for the passcode when the card rejects it. */
async function withPasscode<T>(tangem: Tangem, opts: Opts, label: string, fn: () => Promise<T>): Promise<T> {
  const s = status(opts)
  const prev = tangem.session.opts.onSecurityDelay
  tangem.session.opts.onSecurityDelay = secs => s.message(`Security delay — keep the card on the reader (${Math.ceil(secs)}s)`)
  try {
    for (let attempt = 1; ; attempt++) {
      s.start(label)
      try {
        const result = await fn()
        s.stop('Done')
        return result
      } catch (e) {
        if (!(e instanceof TangemError && e.sw === SW.INVALID_PASSCODE) || !opts.interactive || attempt > 3) {
          s.error(errorMessage(e))
          throw new Reported(errorMessage(e))
        }
        s.stop(pc.yellow(attempt === 1 ? 'This card has a custom passcode' : 'Wrong passcode'))
        tangem.session.passcode = await ask(p.password({ message: 'Passcode (PIN2)', validate: v => (v ? undefined : 'Required') }))
      }
    }
  } finally {
    tangem.session.opts.onSecurityDelay = prev
  }
}

async function withCard(opts: Opts, fn: (tangem: Tangem, card: CardInfo) => Promise<void>) {
  const { tangem, card } = await openCard(opts)
  try {
    await fn(tangem, card)
  } finally {
    tangem.close()
  }
}

async function ask<T>(prompt: Promise<T>): Promise<Exclude<T, symbol>> {
  const value = await prompt
  if (p.isCancel(value)) throw new Cancelled()
  return value as Exclude<T, symbol>
}

function output(opts: Opts, data: unknown, human: () => string) {
  console.log(opts.json ? JSON.stringify(data, null, 2) : human())
}

/** An error already shown to the user (spinner error line). */
class Reported extends Error {}

function errorMessage(e: unknown): string {
  if (e instanceof PcscError && e.noCard) return 'Card removed — keep it on the reader until done'
  return e instanceof Error ? e.message : String(e)
}

main()
  .then(() => process.exit(0))
  .catch(e => {
    if (e instanceof Cancelled) {
      p.cancel('Cancelled')
      process.exit(130)
    }
    const json = process.argv.includes('--json')
    if (json) console.log(JSON.stringify({ error: errorMessage(e) }))
    else if (!(e instanceof Reported) || !process.stdout.isTTY) console.error(pc.red(`✖ ${errorMessage(e)}`))
    process.exit(1)
  })
