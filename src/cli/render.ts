import pc from 'picocolors'
import { formatCardId, type CardInfo, type Wallet } from '../card.ts'
import { NETWORKS, type AccountStatus } from '../networks.ts'

export interface XrplAccount {
  /** undefined = the wallet's own (root) key */
  path?: string
  address: string
  publicKey: string
  /** Present when network lookups were requested */
  networks?: AccountStatus[]
}

export interface WalletView extends Wallet {
  xrpl: XrplAccount[]
}

const row = (label: string, value: string | undefined) =>
  value === undefined || value === '' ? '' : `  ${pc.dim(label.padEnd(16))}${value}\n`

const yesNo = (v?: boolean, yes = 'set', no = 'default') => (v === undefined ? pc.dim('unknown') : v ? yes : no)

export function renderCard(card: CardInfo, wallets: WalletView[]): string {
  const used = card.wallets.length
  const fw = `${card.firmware}${card.firmware.type === 'sdk' ? pc.yellow(' (developer card)') : ''}`
  const health = card.health === 0 ? pc.green('OK') : pc.red(`PROBLEM (${card.health}) — move funds off this card`)
  const delay = card.securityDelayMs ? `${(card.securityDelayMs / 1000).toFixed(1)} s` : 'none'
  const backup = card.backupStatus ? `${card.backupStatus}${card.backupCount ? ` (${card.backupCount} backup cards)` : ''}` : undefined
  const token = card.token
    ? [card.token.symbol, card.token.name, card.token.contract, card.token.decimals !== undefined ? `${card.token.decimals} decimals` : undefined].filter(Boolean).join(' · ')
    : undefined

  let out = `\n  ${pc.bold('Tangem card')}  ${pc.cyan(formatCardId(card.cardId))}${card.cardIdValid ? '' : pc.red('  (CID check digit invalid!)')}\n\n`
  out += row('Status', statusColor(card.status))
  out += row('Firmware', fw)
  out += row('Manufacturer', card.manufacturer)
  out += row('Issuer', card.issuer)
  out += row('Product', card.productMask.join(', ') || productGuess(card))
  out += row('Batch', card.batchId)
  out += row('Manufactured', card.manufactureDate)
  out += row('UID', card.uid)
  out += row('Health', health)
  out += row('Activated', card.isActivated ? undefined : pc.yellow('no — activation required'))
  out += row('Curves', card.supportedCurves.map(c => (c === card.defaultCurve ? pc.bold(c) : c)).join(', ') || pc.dim('none'))
  out += row('Signing', card.signingMethods.join(', '))
  out += row('Encryption', card.encryptionAllowed.join(', '))
  out += row('Security delay', delay)
  out += row('Wallet slots', `${used}/${card.maxWallets} used${card.maxWallets > 1 && card.defaultWalletIndex !== undefined ? pc.dim(` · default #${card.defaultWalletIndex}`) : ''}`)
  out += row('Max signatures', card.maxSignatures?.toLocaleString('en-US'))
  out += row('Access code', yesNo(card.isAccessCodeSet))
  out += row('Passcode', yesNo(card.isPasscodeSet))
  out += row('Backup', backup)
  if (card.settings.includes('requireBackup') && card.backupStatus !== 'active') {
    out += row('', pc.yellow('Backup required: wallets stay unusable until a backup is made (Tangem app)'))
  }
  out += row('Terminal link', card.terminalLink && card.terminalLink !== 'notLinked' ? card.terminalLink : undefined)
  out += row('Blockchain', card.blockchain)
  out += row('Token', token)
  out += row('Settings', wrap(card.settings, 60))
  if (card.userSettings.length) out += row('User settings', card.userSettings.join(', '))
  out += row('Card key', card.cardPublicKey)
  out += row('Issuer key', card.issuerPublicKey)

  out += `\n  ${pc.bold('Wallets')}${wallets.length ? '' : pc.dim('  none')}\n`
  for (const w of wallets) out += renderWallet(w)
  return out
}

export function renderWallet(w: WalletView): string {
  const tags = [w.isPermanent && 'permanent', w.isImported && 'imported', w.hasBackup && 'backed up', w.chainCode && 'HD'].filter(Boolean)
  let out = `\n  ${pc.bold(`#${w.index}`)}  ${w.curve ?? '?'}  ${statusColor(w.status)}${tags.length ? pc.dim(`  (${tags.join(', ')})`) : ''}\n`
  out += row('  Public key', w.publicKey || pc.yellow('unavailable (backup required?)'))
  for (const a of w.xrpl) {
    out += row(a.path ? `  XRPL ${a.path}` : '  XRPL', pc.green(a.address))
    if (a.path) out += row('  Derived key', pc.dim(a.publicKey))
    for (const n of a.networks ?? []) out += row('', renderNetwork(n))
  }
  const signed = [
    w.signedHashes !== undefined ? `${w.signedHashes} signed` : undefined,
    w.remainingSignatures !== undefined ? `${w.remainingSignatures} remaining` : undefined,
  ].filter(Boolean).join(' · ')
  out += row('  Signatures', signed)
  return out
}

export function renderNetwork(n: AccountStatus): string {
  const name = NETWORKS[n.network].name.padEnd(14)
  if (n.error) return `${pc.yellow('?')} ${name} ${pc.yellow(n.error)}`
  if (!n.exists) return `${pc.dim('·')} ${pc.dim(name)} ${pc.dim('not activated')}`
  return `${pc.green('✓')} ${name} ${pc.bold(`${n.balance} ${n.currency}`)} ${pc.dim(`seq ${n.sequence}`)}`
}

function statusColor(s: string) {
  return s === 'loaded' || s === 'backedUp' || s === 'imported' || s === 'backedUpImported' ? pc.green(s)
    : s === 'empty' ? pc.yellow(s)
    : pc.red(s)
}

function productGuess(card: CardInfo) {
  if (card.settings.includes('allowBackup')) return 'Tangem Wallet (backup-capable)'
  if (card.maxWallets > 1) return 'multi-wallet card'
  return undefined
}

function wrap(items: string[], width: number) {
  const lines: string[] = []
  let line = ''
  for (const item of items) {
    if (line && line.length + item.length + 2 > width) { lines.push(line); line = '' }
    line += (line ? ', ' : '') + item
  }
  if (line) lines.push(line)
  return lines.join(`\n${' '.repeat(18)}`)
}
