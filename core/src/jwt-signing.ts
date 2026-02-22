/**
 * @dotdo/oauth - JWT Signing Key Management
 *
 * Manages RSA-2048 signing keys for JWT token issuance.
 * Supports key generation, storage/retrieval, and JWKS export.
 */

import { base64UrlEncode, base64UrlDecode } from './pkce.js'

/**
 * JWT Signing Key with public/private key pair
 */
export interface SigningKey {
  /** Key identifier */
  kid: string
  /** Algorithm (always RS256) */
  alg: 'RS256'
  /** Private key for signing */
  privateKey: CryptoKey
  /** Public key for verification */
  publicKey: CryptoKey
  /** When the key was created */
  createdAt: number
}

/**
 * JWKS format for public key exposure
 */
export interface JWKSPublicKey {
  kty: 'RSA'
  kid: string
  use: 'sig'
  alg: 'RS256'
  n: string
  e: string
}

/**
 * JWKS document format
 */
export interface JWKS {
  keys: JWKSPublicKey[]
}

/**
 * Serialized key for storage
 */
export interface SerializedSigningKey {
  kid: string
  alg: 'RS256'
  privateKeyJwk: JsonWebKey
  publicKeyJwk: JsonWebKey
  createdAt: number
}

/**
 * JWT Claims for access tokens
 */
export interface AccessTokenClaims {
  /** Subject (user ID) */
  sub: string
  /** Client ID */
  client_id: string
  /** Scopes */
  scope?: string
  /** Additional claims */
  [key: string]: unknown
}

/**
 * Generate a new RSA-2048 signing key pair
 */
export async function generateSigningKey(kid?: string): Promise<SigningKey> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true, // extractable
    ['sign', 'verify']
  ) as CryptoKeyPair

  if (!kid) {
    // Derive kid from JWK Thumbprint (RFC 7638) using SHA-256
    const jwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey) as JsonWebKey
    const thumbprintInput = JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n })
    const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(thumbprintInput))
    kid = base64UrlEncode(hash).slice(0, 16)
  }

  return {
    kid,
    alg: 'RS256',
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    createdAt: Date.now(),
  }
}

/**
 * Export a signing key to serializable format for storage
 */
export async function serializeSigningKey(key: SigningKey): Promise<SerializedSigningKey> {
  const [privateKeyJwk, publicKeyJwk] = await Promise.all([
    crypto.subtle.exportKey('jwk', key.privateKey) as Promise<JsonWebKey>,
    crypto.subtle.exportKey('jwk', key.publicKey) as Promise<JsonWebKey>,
  ])

  return {
    kid: key.kid,
    alg: key.alg,
    privateKeyJwk,
    publicKeyJwk,
    createdAt: key.createdAt,
  }
}

/**
 * Import a signing key from serialized format
 */
export async function deserializeSigningKey(serialized: SerializedSigningKey): Promise<SigningKey> {
  const [privateKey, publicKey] = await Promise.all([
    crypto.subtle.importKey(
      'jwk',
      serialized.privateKeyJwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      true,
      ['sign']
    ),
    crypto.subtle.importKey(
      'jwk',
      serialized.publicKeyJwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      true,
      ['verify']
    ),
  ])

  return {
    kid: serialized.kid,
    alg: serialized.alg,
    privateKey,
    publicKey,
    createdAt: serialized.createdAt,
  }
}

/**
 * Export public key to JWKS format
 */
export async function exportPublicKeyToJWKS(key: SigningKey): Promise<JWKSPublicKey> {
  const jwk = await crypto.subtle.exportKey('jwk', key.publicKey) as JsonWebKey

  return {
    kty: 'RSA',
    kid: key.kid,
    use: 'sig',
    alg: 'RS256',
    n: jwk.n!,
    e: jwk.e!,
  }
}

/**
 * Export multiple keys to JWKS document
 */
export async function exportKeysToJWKS(keys: SigningKey[]): Promise<JWKS> {
  const publicKeys = await Promise.all(keys.map(exportPublicKeyToJWKS))
  return { keys: publicKeys }
}

/**
 * Sign a JWT with the given claims
 */
export async function signAccessToken(
  key: SigningKey,
  claims: AccessTokenClaims,
  options: {
    issuer: string
    audience?: string
    expiresIn?: number // seconds, default 3600 (1 hour)
  }
): Promise<string> {
  const { issuer, audience, expiresIn = 3600 } = options
  const now = Math.floor(Date.now() / 1000)

  const header = {
    alg: 'RS256',
    typ: 'JWT',
    kid: key.kid,
  }

  const payload = {
    ...claims,
    iss: issuer,
    ...(audience && { aud: audience }),
    iat: now,
    exp: now + expiresIn,
  }

  const encoder = new TextEncoder()
  const headerB64 = base64UrlEncode(encoder.encode(JSON.stringify(header)).buffer as ArrayBuffer)
  const payloadB64 = base64UrlEncode(encoder.encode(JSON.stringify(payload)).buffer as ArrayBuffer)
  const data = `${headerB64}.${payloadB64}`

  const signature = await crypto.subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' },
    key.privateKey,
    encoder.encode(data)
  )

  const signatureB64 = base64UrlEncode(signature)

  return `${data}.${signatureB64}`
}

/**
 * Signing Key Manager - handles key storage and rotation
 */
export class SigningKeyManager {
  private keys: SigningKey[] = []
  private currentKeyIndex = 0

  constructor(private options: { maxKeys?: number } = {}) {
    this.options.maxKeys = options.maxKeys ?? 2
  }

  /**
   * Get the current signing key, generating one if needed
   */
  async getCurrentKey(): Promise<SigningKey> {
    if (this.keys.length === 0) {
      const key = await generateSigningKey()
      this.keys.push(key)
    }
    return this.keys[this.currentKeyIndex]!
  }

  /**
   * Get all keys (for JWKS endpoint)
   */
  getAllKeys(): SigningKey[] {
    return [...this.keys]
  }

  /**
   * Rotate to a new key
   */
  async rotateKey(): Promise<SigningKey> {
    const newKey = await generateSigningKey()
    this.keys.push(newKey)

    // Remove old keys if we exceed maxKeys
    while (this.keys.length > this.options.maxKeys!) {
      this.keys.shift()
    }

    this.currentKeyIndex = this.keys.length - 1
    return newKey
  }

  /**
   * Load keys from serialized format
   */
  async loadKeys(serializedKeys: SerializedSigningKey[]): Promise<void> {
    this.keys = await Promise.all(serializedKeys.map(deserializeSigningKey))
    this.currentKeyIndex = this.keys.length - 1
  }

  /**
   * Export keys to serializable format
   */
  async exportKeys(): Promise<SerializedSigningKey[]> {
    return Promise.all(this.keys.map(serializeSigningKey))
  }

  /**
   * Export to JWKS format
   */
  async toJWKS(): Promise<JWKS> {
    return exportKeysToJWKS(this.keys)
  }

  /**
   * Sign an access token with the current key
   */
  async signAccessToken(
    claims: AccessTokenClaims,
    options: {
      issuer: string
      audience?: string
      expiresIn?: number
    }
  ): Promise<string> {
    const key = await this.getCurrentKey()
    return signAccessToken(key, claims, options)
  }
}

/**
 * Options for verifyJWTWithKeyManager
 */
export interface VerifyJWTOptions {
  /** Expected issuer claim */
  issuer?: string
  /** Expected audience claim */
  audience?: string | string[]
  /** Clock tolerance in seconds (default: 60) */
  clockTolerance?: number
}

/**
 * Verify a JWT using a SigningKeyManager's keys.
 *
 * Tries all keys in the manager (to support key rotation).
 * Validates signature, exp, iss, and optionally aud claims.
 *
 * @param token - The JWT string to verify
 * @param keyManager - SigningKeyManager with keys to verify against
 * @param options - Optional issuer/audience validation
 * @returns Decoded payload on success, or null on failure
 */
export async function verifyJWTWithKeyManager(
  token: string,
  keyManager: SigningKeyManager,
  options: VerifyJWTOptions = {},
): Promise<AccessTokenClaims & Record<string, unknown> | null> {
  const { issuer, audience, clockTolerance = 60 } = options

  try {
    // Parse the JWT
    const parts = token.split('.')
    if (parts.length !== 3) return null

    const [headerB64, payloadB64, signatureB64] = parts

    let header: { alg: string; kid?: string }
    let payload: Record<string, unknown>
    try {
      header = JSON.parse(atob(headerB64!.replace(/-/g, '+').replace(/_/g, '/')))
      payload = JSON.parse(atob(payloadB64!.replace(/-/g, '+').replace(/_/g, '/')))
    } catch {
      return null
    }

    if (header.alg !== 'RS256') return null

    // Try all keys in the manager (supports rotation)
    const keys = keyManager.getAllKeys()
    if (keys.length === 0) return null

    const encoder = new TextEncoder()
    const data = encoder.encode(`${headerB64}.${payloadB64}`)
    const sigBytes = base64UrlDecode(signatureB64!)

    let signatureValid = false
    for (const key of keys) {
      // If header has kid, only try matching key
      if (header.kid && key.kid !== header.kid) continue
      try {
        const valid = await crypto.subtle.verify(
          { name: 'RSASSA-PKCS1-v1_5' },
          key.publicKey,
          sigBytes,
          data,
        )
        if (valid) {
          signatureValid = true
          break
        }
      } catch {
        continue
      }
    }

    if (!signatureValid) return null

    const now = Math.floor(Date.now() / 1000)

    // Validate exp
    if (typeof payload['exp'] === 'number' && now > payload['exp'] + clockTolerance) {
      return null
    }

    // Validate iss
    if (issuer !== undefined && payload['iss'] !== issuer) {
      return null
    }

    // Validate aud
    if (audience !== undefined) {
      const tokenAud = Array.isArray(payload['aud']) ? payload['aud'] : payload['aud'] ? [payload['aud']] : []
      const expectedAud = Array.isArray(audience) ? audience : [audience]
      if (!expectedAud.some((a) => tokenAud.includes(a))) {
        return null
      }
    }

    return payload as AccessTokenClaims & Record<string, unknown>
  } catch {
    return null
  }
}
