/** Tangem COS protocol constants (Tangem Card Specification v6.33 + tangem-sdk). */

export const INS = {
  PERSONALIZE: 0xf1,
  READ: 0xf2,
  ATTEST_CARD_KEY: 0xf3,
  ATTEST_CARD_UNIQUENESS: 0xf4,
  ATTEST_CARD_FIRMWARE: 0xf5,
  WRITE_ISSUER_DATA: 0xf6,
  READ_ISSUER_DATA: 0xf7,
  CREATE_WALLET: 0xf8,
  ATTEST_WALLET_KEY: 0xf9,
  SET_PIN: 0xfa,
  SIGN: 0xfb,
  PURGE_WALLET: 0xfc,
  ACTIVATE: 0xfe,
  OPEN_SESSION: 0xff,
  GET_ENTROPY: 0xe7,
} as const

/** READ command interaction modes (tag 0x23). */
export const READ_MODE = { CARD: 0x01, WALLET: 0x02, WALLETS_LIST: 0x03 } as const

export const TAG = {
  CARD_ID: 0x01,
  STATUS: 0x02,
  CARD_PUBLIC_KEY: 0x03,
  CARD_SIGNATURE: 0x04,
  CURVE_ID: 0x05,
  HASH_ALG_ID: 0x06,
  SIGNING_METHOD: 0x07,
  MAX_SIGNATURES: 0x08,
  PAUSE_BEFORE_PIN2: 0x09,
  SETTINGS_MASK: 0x0a,
  UID: 0x0b,
  CARD_DATA: 0x0c,
  NDEF_DATA: 0x0d,
  HEALTH: 0x0f,
  PIN: 0x10,
  PIN2: 0x11,
  CHALLENGE: 0x16,
  SALT: 0x17,
  CVC: 0x19,
  SESSION_KEY_A: 0x1a,
  SESSION_KEY_B: 0x1b,
  PAUSE: 0x1c,
  MANUFACTURER_NAME: 0x20,
  INTERACTION_MODE: 0x23,
  FLASH: 0x28,
  LEGACY_MODE: 0x29,
  USER_SETTINGS_MASK: 0x2f,
  ISSUER_PUBLIC_KEY: 0x30,
  IS_ACTIVATED: 0x3a,
  IS_LINKED: 0x58,
  TERMINAL_LINK_STATE: 0x5f,
  PIN2_IS_DEFAULT: 0x59,
  PIN_IS_DEFAULT: 0x5a,
  WALLET_PUBLIC_KEY: 0x60,
  WALLET_SIGNATURE: 0x61,
  WALLET_REMAINING_SIGNATURES: 0x62,
  WALLET_SIGNED_HASHES: 0x63,
  CHECK_WALLET_COUNTER: 0x64,
  WALLET_INDEX: 0x65,
  WALLETS_COUNT: 0x66,
  CARD_WALLET: 0x68,
  WALLET_HD_PATH: 0x6a,
  WALLET_HD_CHAIN: 0x6b,
  FIRMWARE_VERSION: 0x80,
  BATCH_ID: 0x81,
  MANUFACTURE_DATE_TIME: 0x82,
  ISSUER_NAME: 0x83,
  BLOCKCHAIN_NAME: 0x84,
  CARD_ID_MANUFACTURER_SIGNATURE: 0x86,
  PRODUCT_MASK: 0x8a,
  TOKEN_SYMBOL: 0xa0,
  TOKEN_CONTRACT_ADDRESS: 0xa1,
  TOKEN_DECIMAL: 0xa2,
  TOKEN_NAME: 0xa3,
  PROOF: 0xaa,
  BACKUP_STATUS: 0xd0,
  BACKUP_COUNT: 0xd1,
} as const

export const SW = {
  PROCESS_COMPLETED: 0x9000,
  PIN1_CHANGED: 0x9001,
  PIN2_CHANGED: 0x9002,
  PINS12_CHANGED: 0x9003,
  PIN3_CHANGED: 0x9004,
  PINS13_CHANGED: 0x9005,
  PINS23_CHANGED: 0x9006,
  PINS123_CHANGED: 0x9007,
  NEED_PAUSE: 0x9789,
  NEED_ENCRYPTION: 0x6982,
  NEED_RESET: 0x6983,
  INVALID_STATE: 0x6985,
  ERROR_PROCESSING_COMMAND: 0x6286,
  FILE_NOT_FOUND: 0x6a82,
  INVALID_PARAMS: 0x6a86,
  WALLET_NOT_FOUND: 0x6a88,
  WALLET_ALREADY_EXISTS: 0x6a89,
  INVALID_ACCESS_CODE: 0x6af1,
  INVALID_PASSCODE: 0x6af2,
  ACCESS_DENIED: 0x6af3,
  INS_NOT_SUPPORTED: 0x6d00,
} as const

export const SW_MESSAGE: Record<number, string> = {
  [SW.NEED_ENCRYPTION]: 'Card requires (stronger) encryption',
  [SW.NEED_RESET]: 'Card needs reset',
  [SW.INVALID_STATE]: 'Card is in an invalid state for this command',
  [SW.ERROR_PROCESSING_COMMAND]: 'Card internal error while processing command',
  [SW.FILE_NOT_FOUND]: 'File not found',
  [SW.INVALID_PARAMS]: 'Invalid parameters (wrong access code / passcode?)',
  [SW.WALLET_NOT_FOUND]: 'Wallet not found',
  [SW.WALLET_ALREADY_EXISTS]: 'Wallet already exists',
  [SW.INVALID_ACCESS_CODE]: 'Invalid access code (PIN1)',
  [SW.INVALID_PASSCODE]: 'Invalid passcode (PIN2)',
  [SW.ACCESS_DENIED]: 'Access denied',
  [SW.INS_NOT_SUPPORTED]: 'Command not supported by this card',
}

export const isSuccess = (sw: number) => sw === SW.PROCESS_COMPLETED || (sw >= SW.PIN1_CHANGED && sw <= SW.PINS123_CHANGED)

export const CARD_STATUS: Record<number, CardStatus> = { 0: 'notPersonalized', 1: 'empty', 2: 'loaded', 3: 'purged' }
export type CardStatus = 'notPersonalized' | 'empty' | 'loaded' | 'purged'

export const WALLET_STATUS: Record<number, string> = {
  0x01: 'empty',
  0x02: 'loaded',
  0x03: 'purged',
  0x42: 'imported',
  0x81: 'emptyBackedUp',
  0x82: 'backedUp',
  0x83: 'backedUpAndPurged',
  0xc2: 'backedUpImported',
}
/** Wallet statuses that hold a usable key. */
export const WALLET_AVAILABLE = new Set([0x02, 0x42, 0x82, 0xc2])

export const CURVES = [
  'secp256k1',
  'ed25519',
  'ed25519_slip0010',
  'secp256r1',
  'bip0340',
  'bls12381_G2',
  'bls12381_G2_AUG',
  'bls12381_G2_POP',
] as const
export type Curve = (typeof CURVES)[number]

export const CARD_SETTINGS: Record<string, number> = {
  isReusable: 0x0001,
  useActivation: 0x0002,
  permanentWallet: 0x0004, // a.k.a. ProhibitPurgeWallet
  useBlock: 0x0008,
  allowSetPIN1: 0x0010,
  allowSetPIN2: 0x0020,
  useCvc: 0x0040,
  prohibitDefaultPIN1: 0x0080,
  useOneCommandAtTime: 0x0100,
  useNDEF: 0x0200,
  useDynamicNDEF: 0x0400,
  smartSecurityDelay: 0x0800,
  allowUnencrypted: 0x1000,
  allowFastEncryption: 0x2000,
  protectIssuerDataAgainstReplay: 0x4000,
  allowSelectBlockchain: 0x8000,
  disablePrecomputedNDEF: 0x00010000,
  skipSecurityDelayIfValidatedByIssuer: 0x00020000,
  skipCheckPIN2CVCIfValidatedByIssuer: 0x00040000,
  skipSecurityDelayIfValidatedByLinkedTerminal: 0x00080000,
  restrictOverwriteIssuerExtraData: 0x00100000,
  allowHDWallets: 0x00200000,
  allowBackup: 0x00400000,
  allowKeysImport: 0x00800000,
  disableIssuerData: 0x01000000,
  disableUserData: 0x02000000,
  disableFiles: 0x04000000,
  requireBackup: 0x08000000,
}

export const USER_SETTINGS: Record<string, number> = {
  forbidResetPIN: 0x00000001,
  requirePIN: 0x00000002,
  disableNDEF: 0x00000010,
}

export const WALLET_SETTINGS = { isReusable: 0x0001, isPermanent: 0x0004 } as const

export const SIGNING_METHODS: Record<string, number> = {
  signHash: 0,
  signRaw: 1,
  signHashSignedByIssuer: 2,
  signRawSignedByIssuer: 3,
  signHashSignedByIssuerAndUpdateIssuerData: 4,
  signRawSignedByIssuerAndUpdateIssuerData: 5,
  signPos: 6,
}
/** SigningMethod.signHash as a "set of methods" byte (high bit set). */
export const SIGNING_METHOD_SIGN_HASH = 0x81

export const PRODUCT_MASK: Record<string, number> = {
  note: 0x01,
  tag: 0x02,
  idCard: 0x04,
  idIssuer: 0x08,
  authentication: 0x10,
  twinCard: 0x20,
}

export const BACKUP_STATUS: Record<number, string> = { 0: 'noBackup', 1: 'cardLinked', 2: 'active' }

export const TERMINAL_LINK: Record<number, string> = { 0: 'notLinked', 1: 'linkedToAnother', 2: 'linked' }

export const ENCRYPTION = { none: 0x00, fast: 0x01, strong: 0x02 } as const
export type EncryptionMode = keyof typeof ENCRYPTION

/** Firmware feature thresholds. */
export const FW = {
  multiwallet: [4, 0],
  passcodeStatus: [4, 1],
  createWalletResponse: [4, 25],
  userCodeStatuses: [4, 33],
  defaultPinsOptional: [4, 34],
  hdWallet: [4, 39],
  backup: [4, 39],
  bls: [4, 45],
  keysImport: [6, 21],
  ed25519Slip0010: [6, 33],
  v8: [8, 59],
} as const satisfies Record<string, readonly [number, number]>

export const DEFAULT_ACCESS_CODE = '000000'
export const DEFAULT_PASSCODE = '000'

/** XRP Ledger BIP44 path as used by Tangem apps (secp256k1). */
export const XRPL_DERIVATION_PATH = "m/44'/144'/0'/0/0"
