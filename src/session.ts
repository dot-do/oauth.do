/**
 * oauth.do/session - Cookie-based session management with AES-GCM encryption
 *
 * Secure session encoding/decoding using Web Crypto API.
 * Zero dependencies - works in all environments that support Web Crypto.
 *
 * @example
 * ```ts
 * import { encodeSession, decodeSession } from 'oauth.do/session'
 *
 * const session = { userId: 'user_123', accessToken: 'tok_abc' }
 * const encoded = await encodeSession(session, 'my-secret-key')
 * const decoded = await decodeSession(encoded, 'my-secret-key')
 * ```
 */

// ─────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────

/**
 * Session data stored in encrypted cookie
 */
export interface SessionData {
  userId: string
  organizationId?: string
  email?: string
  name?: string
  accessToken: string
  refreshToken?: string
  expiresAt?: number
  /** Extensible: apps can add custom fields */
  [key: string]: unknown
}

/**
 * Configuration for session management
 */
export interface SessionConfig {
  /** Cookie name (default: 'session') */
  cookieName: string
  /** Cookie max age in seconds (default: 604800 = 7 days) */
  cookieMaxAge: number
  /** Cookie secure flag (default: true) */
  cookieSecure: boolean
  /** Cookie SameSite attribute (default: 'lax') */
  cookieSameSite: 'strict' | 'lax' | 'none'
  /** Encryption secret (required in production) */
  secret: string
}

/**
 * Generate a random development secret.
 * This is used only in non-production environments when SESSION_SECRET is not set.
 */
function generateDevSecret(): string {
  const array = new Uint8Array(32)
  crypto.getRandomValues(array)
  return Array.from(array, (b) => b.toString(16).padStart(2, '0')).join('')
}

// Cache the dev secret so it remains consistent during a single process lifetime
let cachedDevSecret: string | null = null

/**
 * Get the session secret with proper environment checks.
 * - In production (NODE_ENV === 'production'), SESSION_SECRET is required
 * - In development, a random secret is generated if not provided (with a warning)
 */
function getSecretWithValidation(envSecret?: string): string {
  if (envSecret) {
    return envSecret
  }

  const isProduction = typeof process !== 'undefined' && process.env?.NODE_ENV === 'production'

  if (isProduction) {
    throw new Error('SESSION_SECRET environment variable is required in production')
  }

  // In development, generate and cache a random secret
  if (!cachedDevSecret) {
    cachedDevSecret = generateDevSecret()
    console.warn(
      '[oauth.do/session] WARNING: No SESSION_SECRET provided. Using a randomly generated secret for this session. ' +
      'Sessions will not persist across server restarts. Set SESSION_SECRET environment variable to fix this.'
    )
  }

  return cachedDevSecret
}

/**
 * Default session configuration (without secret - must be provided or generated)
 */
export const defaultSessionConfig: Omit<SessionConfig, 'secret'> & { secret?: string } = {
  cookieName: 'session',
  cookieMaxAge: 60 * 60 * 24 * 7, // 7 days
  cookieSecure: true,
  cookieSameSite: 'lax',
}

// ─────────────────────────────────────────────────────────────────
// AES-GCM Encryption
// ─────────────────────────────────────────────────────────────────

const ALGORITHM = 'AES-GCM'
const IV_LENGTH = 12
const TAG_LENGTH = 128

/**
 * Derive an AES-GCM encryption key from a secret string using PBKDF2.
 *
 * Uses 100,000 iterations of PBKDF2-SHA-256 with a static application salt.
 * This is a significant security improvement over the previous approach of
 * padding/truncating the secret to 32 bytes.
 */
async function deriveKey(secret: string): Promise<CryptoKey> {
  const encoder = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(secret), 'PBKDF2', false, ['deriveKey'])
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: encoder.encode('oauth.do-session-v1'),
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: ALGORITHM, length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

/**
 * Derive an AES-GCM encryption key using the legacy (weak) method.
 * Kept only for backwards-compatible decryption of existing sessions.
 * @deprecated Use deriveKey() for all new encryption.
 */
async function getLegacyEncryptionKey(secret: string): Promise<CryptoKey> {
  const encoder = new TextEncoder()
  return crypto.subtle.importKey('raw', encoder.encode(secret.padEnd(32, '0').slice(0, 32)), { name: ALGORITHM }, false, ['encrypt', 'decrypt'])
}

/**
 * Cache for derived keys to avoid repeated PBKDF2 computation.
 * Maps secret string to { key, legacyKey } pair.
 */
const keyCache = new Map<string, { key: CryptoKey; legacyKey?: CryptoKey }>()

/**
 * Get the PBKDF2-derived encryption key for a secret, with caching.
 */
async function getEncryptionKey(secret: string): Promise<CryptoKey> {
  const cached = keyCache.get(secret)
  if (cached) return cached.key
  const key = await deriveKey(secret)
  keyCache.set(secret, { key })
  return key
}

/**
 * Get the legacy encryption key for a secret, with caching.
 */
async function getLegacyKey(secret: string): Promise<CryptoKey> {
  const cached = keyCache.get(secret)
  if (cached?.legacyKey) return cached.legacyKey
  const legacyKey = await getLegacyEncryptionKey(secret)
  const existing = keyCache.get(secret)
  if (existing) {
    existing.legacyKey = legacyKey
  } else {
    keyCache.set(secret, { key: await deriveKey(secret), legacyKey })
  }
  return legacyKey
}

/**
 * Encode session data with AES-GCM encryption.
 * Format: base64(IV || ciphertext || auth tag)
 *
 * @param session - Session data to encrypt
 * @param secret - Encryption secret (min 16 chars recommended)
 * @returns Base64-encoded encrypted session string
 */
export async function encodeSession(session: SessionData, secret?: string): Promise<string> {
  const key = await getEncryptionKey(secret ?? getSecretWithValidation(defaultSessionConfig.secret))
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH))
  const encoder = new TextEncoder()
  const data = encoder.encode(JSON.stringify(session))

  const ciphertext = await crypto.subtle.encrypt(
    { name: ALGORITHM, iv, tagLength: TAG_LENGTH },
    key,
    data
  )

  // Combine IV + ciphertext (ciphertext includes auth tag)
  const combined = new Uint8Array(iv.length + ciphertext.byteLength)
  combined.set(iv, 0)
  combined.set(new Uint8Array(ciphertext), iv.length)

  return btoa(String.fromCharCode(...combined))
}

/**
 * Attempt to decrypt a combined IV+ciphertext buffer with the given key.
 * Returns the parsed SessionData on success, or null on failure.
 */
async function tryDecrypt(combined: Uint8Array, key: CryptoKey): Promise<SessionData | null> {
  try {
    const iv = combined.slice(0, IV_LENGTH)
    const ciphertext = combined.slice(IV_LENGTH)

    const decrypted = await crypto.subtle.decrypt({ name: ALGORITHM, iv, tagLength: TAG_LENGTH }, key, ciphertext)

    const decoder = new TextDecoder()
    const parsed: unknown = JSON.parse(decoder.decode(decrypted))

    if (!isValidSessionData(parsed)) {
      return null
    }

    return parsed
  } catch {
    return null
  }
}

/**
 * Decode session data with AES-GCM decryption.
 * Returns null if decryption fails or data is invalid.
 *
 * Migration path: tries PBKDF2-derived key first, then falls back to the
 * legacy padded key for sessions encrypted before the KDF upgrade. Sessions
 * decrypted via the legacy path are flagged via `_needsReEncrypt` so that
 * callers can transparently re-encrypt with the new KDF.
 *
 * @param encoded - Base64-encoded encrypted session string
 * @param secret - Encryption secret (must match the one used for encoding)
 * @returns Decoded session data or null
 */
export async function decodeSession(encoded: string, secret?: string): Promise<SessionData | null> {
  try {
    const resolvedSecret = secret ?? getSecretWithValidation(defaultSessionConfig.secret)
    const combined = Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0))

    // Try new PBKDF2-derived key first
    const key = await getEncryptionKey(resolvedSecret)
    const result = await tryDecrypt(combined, key)
    if (result) return result

    // Fallback: try legacy key (padding/truncation)
    const legacy = await getLegacyKey(resolvedSecret)
    const legacyResult = await tryDecrypt(combined, legacy)
    if (legacyResult) {
      // Mark session as needing re-encryption with the new KDF.
      // This flag is non-enumerable so it won't leak into JSON serialization,
      // but callers (e.g. middleware) can check it to transparently upgrade.
      Object.defineProperty(legacyResult, '_needsReEncrypt', { value: true, enumerable: false })
      return legacyResult
    }

    return null
  } catch {
    return null
  }
}

/**
 * Validate that session data has the required structure
 */
export function isValidSessionData(data: unknown): data is SessionData {
  if (data === null || typeof data !== 'object') {
    return false
  }

  const session = data as Record<string, unknown>

  // Required fields
  if (typeof session.userId !== 'string' || session.userId.length === 0) {
    return false
  }
  if (typeof session.accessToken !== 'string' || session.accessToken.length === 0) {
    return false
  }

  // Optional fields type validation
  if (session.organizationId !== undefined && typeof session.organizationId !== 'string') {
    return false
  }
  if (session.email !== undefined && typeof session.email !== 'string') {
    return false
  }
  if (session.name !== undefined && typeof session.name !== 'string') {
    return false
  }
  if (session.refreshToken !== undefined && typeof session.refreshToken !== 'string') {
    return false
  }
  if (session.expiresAt !== undefined && typeof session.expiresAt !== 'number') {
    return false
  }

  return true
}

/**
 * Get session config from environment variables with defaults.
 *
 * Environment variables:
 * - SESSION_SECRET: Encryption secret
 * - SESSION_COOKIE_NAME: Cookie name
 * - SESSION_COOKIE_MAX_AGE: Cookie max age in seconds
 * - SESSION_COOKIE_SECURE: 'true' or 'false'
 * - SESSION_COOKIE_SAME_SITE: 'strict', 'lax', or 'none'
 */
export function getSessionConfig(env?: Record<string, string | undefined>): SessionConfig {
  const validSameSite = ['strict', 'lax', 'none'] as const

  let cookieSameSite: SessionConfig['cookieSameSite'] = defaultSessionConfig.cookieSameSite
  if (env?.SESSION_COOKIE_SAME_SITE) {
    const value = env.SESSION_COOKIE_SAME_SITE
    if (validSameSite.includes(value as typeof validSameSite[number])) {
      cookieSameSite = value as SessionConfig['cookieSameSite']
    }
  }

  let cookieMaxAge = defaultSessionConfig.cookieMaxAge
  if (env?.SESSION_COOKIE_MAX_AGE) {
    const parsed = parseInt(env.SESSION_COOKIE_MAX_AGE, 10)
    if (!Number.isNaN(parsed) && parsed > 0) {
      cookieMaxAge = parsed
    }
  }

  return {
    secret: getSecretWithValidation(env?.SESSION_SECRET),
    cookieName: env?.SESSION_COOKIE_NAME ?? defaultSessionConfig.cookieName,
    cookieMaxAge,
    cookieSecure: env?.SESSION_COOKIE_SECURE !== 'false',
    cookieSameSite,
  }
}
