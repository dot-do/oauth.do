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
 * Default session configuration
 */
export const defaultSessionConfig: SessionConfig = {
  cookieName: 'session',
  cookieMaxAge: 60 * 60 * 24 * 7, // 7 days
  cookieSecure: true,
  cookieSameSite: 'lax',
  secret: 'oauth-do-dev-secret-change-in-production',
}

// ─────────────────────────────────────────────────────────────────
// AES-GCM Encryption
// ─────────────────────────────────────────────────────────────────

const ALGORITHM = 'AES-GCM'
const IV_LENGTH = 12
const TAG_LENGTH = 128

/**
 * Derive an AES-GCM encryption key from a secret string
 */
async function getEncryptionKey(secret: string): Promise<CryptoKey> {
  const encoder = new TextEncoder()
  return crypto.subtle.importKey(
    'raw',
    encoder.encode(secret.padEnd(32, '0').slice(0, 32)),
    { name: ALGORITHM },
    false,
    ['encrypt', 'decrypt']
  )
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
  const key = await getEncryptionKey(secret ?? defaultSessionConfig.secret)
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
 * Decode session data with AES-GCM decryption.
 * Returns null if decryption fails or data is invalid.
 *
 * @param encoded - Base64-encoded encrypted session string
 * @param secret - Encryption secret (must match the one used for encoding)
 * @returns Decoded session data or null
 */
export async function decodeSession(encoded: string, secret?: string): Promise<SessionData | null> {
  try {
    const key = await getEncryptionKey(secret ?? defaultSessionConfig.secret)
    const combined = Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0))

    const iv = combined.slice(0, IV_LENGTH)
    const ciphertext = combined.slice(IV_LENGTH)

    const decrypted = await crypto.subtle.decrypt(
      { name: ALGORITHM, iv, tagLength: TAG_LENGTH },
      key,
      ciphertext
    )

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
    secret: env?.SESSION_SECRET ?? defaultSessionConfig.secret,
    cookieName: env?.SESSION_COOKIE_NAME ?? defaultSessionConfig.cookieName,
    cookieMaxAge,
    cookieSecure: env?.SESSION_COOKIE_SECURE !== 'false',
    cookieSameSite,
  }
}
