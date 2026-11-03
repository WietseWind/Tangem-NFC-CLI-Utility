/** Account presence / balance lookups on XRPL & Xahau via public JSON-RPC endpoints. */

export const NETWORKS = {
  xrpl: { name: 'XRPL Mainnet', url: 'https://xrplcluster.com', currency: 'XRP' },
  'xrpl-testnet': { name: 'XRPL Testnet', url: 'https://testnet.xrpl-labs.com', currency: 'XRP' },
  xahau: { name: 'Xahau Mainnet', url: 'https://xahau.network', currency: 'XAH' },
  'xahau-testnet': { name: 'Xahau Testnet', url: 'https://xahau-test.net', currency: 'XAH' },
} as const

export type NetworkId = keyof typeof NETWORKS
export const NETWORK_IDS = Object.keys(NETWORKS) as NetworkId[]

export interface AccountStatus {
  network: NetworkId
  /** undefined when the lookup itself failed (see `error`) */
  exists?: boolean
  /** Balance in XRP / XAH (decimal string) */
  balance?: string
  currency: string
  sequence?: number
  error?: string
}

export async function accountInfo(network: NetworkId, account: string, timeoutMs = 8000): Promise<AccountStatus> {
  const { url, currency } = NETWORKS[network]
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ method: 'account_info', params: [{ account, ledger_index: 'validated' }] }),
      signal: AbortSignal.timeout(timeoutMs),
    })
    if (!res.ok) return { network, currency, error: `HTTP ${res.status}` }
    const { result } = (await res.json()) as { result?: { error?: string; error_message?: string; account_data?: { Balance: string; Sequence: number } } }
    if (result?.error === 'actNotFound') return { network, currency, exists: false }
    if (result?.error) return { network, currency, error: result.error_message ?? result.error }
    if (!result?.account_data) return { network, currency, error: 'Unexpected response' }
    return {
      network,
      currency,
      exists: true,
      balance: dropsToUnits(result.account_data.Balance),
      sequence: result.account_data.Sequence,
    }
  } catch (e) {
    return { network, currency, error: e instanceof Error && e.name === 'TimeoutError' ? 'timeout' : String((e as Error)?.message ?? e) }
  }
}

/** Look up one account on several networks in parallel. */
export const checkAccount = (account: string, networks: NetworkId[] = NETWORK_IDS) =>
  Promise.all(networks.map(n => accountInfo(n, account)))

export function dropsToUnits(drops: string): string {
  const n = BigInt(drops)
  const whole = n / 1_000_000n
  const frac = (n % 1_000_000n).toString().padStart(6, '0').replace(/0+$/, '')
  return frac ? `${whole}.${frac}` : `${whole}`
}

/** Parse "xrpl,xahau-testnet" / "all"; aliases: mainnet, testnet. */
export function parseNetworks(list: string): NetworkId[] {
  const out = new Set<NetworkId>()
  for (const raw of list.split(',').map(s => s.trim().toLowerCase()).filter(Boolean)) {
    if (raw === 'all') NETWORK_IDS.forEach(n => out.add(n))
    else if (raw === 'mainnet') ['xrpl', 'xahau'].forEach(n => out.add(n as NetworkId))
    else if (raw === 'testnet') ['xrpl-testnet', 'xahau-testnet'].forEach(n => out.add(n as NetworkId))
    else if (raw in NETWORKS) out.add(raw as NetworkId)
    else throw new Error(`Unknown network "${raw}". Options: all, mainnet, testnet, ${NETWORK_IDS.join(', ')}`)
  }
  return [...out]
}
