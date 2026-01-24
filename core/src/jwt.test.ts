import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { verifyJWT, decodeJWT, isJWTExpired, clearJWKSCache } from './jwt.js'
import type { JWTVerifyOptions } from './jwt.js'

// Test keys generated for testing purposes
// These are NOT production keys - for testing only

// RSA key pair for RS256 testing
const testRSAPrivateKey = {
  kty: 'RSA',
  n: 'sXchDaQebSXKcvN9RdHzpkXE-wWqPGq5WzGd8UVW7mVOj-VLNHDzCqJW9DlWPL-6M2uqT_6HgCBjz_XR1pY6wNxZQlR_Ywd8kkwS-Qz-3KU3ZT_5uQVN4e3Zk0u1e6j4LOV2q9T_7J5Q6p3W6T_7J5Q6p3W6T_7J5Q6p3W6T8',
  e: 'AQAB',
  d: 'VFCWOqXr8nvZNyaaJLXE3s9KFp9n6R93BcyKOCUc9Y7T5VzN4j8YPMG8RnQ5Y9T5VzN4j8YPMG8RnQ5Y9T5VzN4j8YPMG8RnQ5Y9T5VzN4j8YPMG8RnQ5Y9T5VzN',
  alg: 'RS256',
}

// Helper to create a valid JWT for testing
async function createTestJWT(
  payload: Record<string, unknown>,
  privateKey: CryptoKey,
  header: { alg: string; kid?: string } = { alg: 'RS256' }
): Promise<string> {
  const headerB64 = btoa(JSON.stringify({ typ: 'JWT', ...header }))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')

  const payloadB64 = btoa(JSON.stringify(payload))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')

  const data = `${headerB64}.${payloadB64}`
  const encoder = new TextEncoder()
  const dataBytes = encoder.encode(data)

  const signature = await crypto.subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' },
    privateKey,
    dataBytes
  )

  const signatureB64 = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')

  return `${data}.${signatureB64}`
}

// Generate RSA key pair for testing
async function generateRSAKeyPair(): Promise<{ privateKey: CryptoKey; publicKey: CryptoKey }> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify']
  )

  return { privateKey: keyPair.privateKey, publicKey: keyPair.publicKey }
}

// Generate EC key pair for testing
async function generateECKeyPair(): Promise<{ privateKey: CryptoKey; publicKey: CryptoKey }> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    true,
    ['sign', 'verify']
  )

  return { privateKey: keyPair.privateKey, publicKey: keyPair.publicKey }
}

// Helper to create ES256 JWT
async function createES256JWT(
  payload: Record<string, unknown>,
  privateKey: CryptoKey,
  header: { alg: string; kid?: string } = { alg: 'ES256' }
): Promise<string> {
  const headerB64 = btoa(JSON.stringify({ typ: 'JWT', ...header }))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')

  const payloadB64 = btoa(JSON.stringify(payload))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')

  const data = `${headerB64}.${payloadB64}`
  const encoder = new TextEncoder()
  const dataBytes = encoder.encode(data)

  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    dataBytes
  )

  const signatureB64 = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')

  return `${data}.${signatureB64}`
}

describe('JWT Verification', () => {
  let rsaKeyPair: { privateKey: CryptoKey; publicKey: CryptoKey }

  beforeEach(async () => {
    rsaKeyPair = await generateRSAKeyPair()
    clearJWKSCache()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('verifyJWT', () => {
    it('verifies a valid RS256 token', async () => {
      const now = Math.floor(Date.now() / 1000)
      const token = await createTestJWT(
        {
          sub: 'user-123',
          iss: 'https://issuer.com',
          aud: 'my-api',
          exp: now + 3600,
          iat: now,
        },
        rsaKeyPair.privateKey
      )

      const result = await verifyJWT(token, {
        publicKey: rsaKeyPair.publicKey,
        issuer: 'https://issuer.com',
        audience: 'my-api',
      })

      expect(result.valid).toBe(true)
      expect(result.payload?.sub).toBe('user-123')
      expect(result.payload?.iss).toBe('https://issuer.com')
      expect(result.header?.alg).toBe('RS256')
    })

    it('rejects token with invalid format', async () => {
      const result = await verifyJWT('not.a.valid.jwt.format', {})

      expect(result.valid).toBe(false)
      expect(result.error).toContain('Invalid JWT format')
    })

    it('rejects token with only 2 parts', async () => {
      const result = await verifyJWT('header.payload', {})

      expect(result.valid).toBe(false)
      expect(result.error).toContain('Invalid JWT format')
    })

    it('rejects token with invalid header', async () => {
      const result = await verifyJWT('!!!.payload.signature', {})

      expect(result.valid).toBe(false)
      expect(result.error).toContain('Invalid JWT header')
    })

    it('rejects token with invalid payload', async () => {
      const headerB64 = btoa(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '')

      const result = await verifyJWT(`${headerB64}.!!!.signature`, {})

      expect(result.valid).toBe(false)
      expect(result.error).toContain('Invalid JWT payload')
    })

    it('rejects unsupported algorithm', async () => {
      const headerB64 = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '')
      const payloadB64 = btoa(JSON.stringify({ sub: 'test' }))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '')

      const result = await verifyJWT(`${headerB64}.${payloadB64}.signature`, {
        publicKey: rsaKeyPair.publicKey,
      })

      expect(result.valid).toBe(false)
      expect(result.error).toContain('Unsupported algorithm')
    })

    it('requires jwksUrl or publicKey', async () => {
      const token = await createTestJWT(
        { sub: 'user-123' },
        rsaKeyPair.privateKey
      )

      const result = await verifyJWT(token, {})

      expect(result.valid).toBe(false)
      expect(result.error).toContain('Either jwksUrl or publicKey must be provided')
    })

    it('rejects token with invalid signature', async () => {
      const token = await createTestJWT(
        { sub: 'user-123' },
        rsaKeyPair.privateKey
      )

      // Create a different key pair
      const otherKeyPair = await generateRSAKeyPair()

      const result = await verifyJWT(token, {
        publicKey: otherKeyPair.publicKey,
      })

      expect(result.valid).toBe(false)
      expect(result.error).toContain('Invalid signature')
    })

    it('rejects expired token', async () => {
      const now = Math.floor(Date.now() / 1000)
      const token = await createTestJWT(
        {
          sub: 'user-123',
          exp: now - 3600, // Expired 1 hour ago
          iat: now - 7200,
        },
        rsaKeyPair.privateKey
      )

      const result = await verifyJWT(token, {
        publicKey: rsaKeyPair.publicKey,
      })

      expect(result.valid).toBe(false)
      expect(result.error).toContain('expired')
    })

    it('allows expired token with ignoreExpiration option', async () => {
      const now = Math.floor(Date.now() / 1000)
      const token = await createTestJWT(
        {
          sub: 'user-123',
          exp: now - 3600,
          iat: now - 7200,
        },
        rsaKeyPair.privateKey
      )

      const result = await verifyJWT(token, {
        publicKey: rsaKeyPair.publicKey,
        ignoreExpiration: true,
      })

      expect(result.valid).toBe(true)
      expect(result.payload?.sub).toBe('user-123')
    })

    it('respects clock tolerance for expiration', async () => {
      const now = Math.floor(Date.now() / 1000)
      const token = await createTestJWT(
        {
          sub: 'user-123',
          exp: now - 30, // Expired 30 seconds ago
          iat: now - 3600,
        },
        rsaKeyPair.privateKey
      )

      const result = await verifyJWT(token, {
        publicKey: rsaKeyPair.publicKey,
        clockTolerance: 60, // 60 seconds tolerance
      })

      expect(result.valid).toBe(true)
    })

    it('rejects token issued in the future', async () => {
      const now = Math.floor(Date.now() / 1000)
      const token = await createTestJWT(
        {
          sub: 'user-123',
          iat: now + 3600, // Issued 1 hour in the future
          exp: now + 7200,
        },
        rsaKeyPair.privateKey
      )

      const result = await verifyJWT(token, {
        publicKey: rsaKeyPair.publicKey,
      })

      expect(result.valid).toBe(false)
      expect(result.error).toContain('issued in the future')
    })

    it('rejects token not yet valid (nbf)', async () => {
      const now = Math.floor(Date.now() / 1000)
      const token = await createTestJWT(
        {
          sub: 'user-123',
          nbf: now + 3600, // Not valid for another hour
          exp: now + 7200,
          iat: now,
        },
        rsaKeyPair.privateKey
      )

      const result = await verifyJWT(token, {
        publicKey: rsaKeyPair.publicKey,
      })

      expect(result.valid).toBe(false)
      expect(result.error).toContain('not yet valid')
    })

    it('validates issuer claim', async () => {
      const now = Math.floor(Date.now() / 1000)
      const token = await createTestJWT(
        {
          sub: 'user-123',
          iss: 'https://wrong-issuer.com',
          exp: now + 3600,
          iat: now,
        },
        rsaKeyPair.privateKey
      )

      const result = await verifyJWT(token, {
        publicKey: rsaKeyPair.publicKey,
        issuer: 'https://expected-issuer.com',
      })

      expect(result.valid).toBe(false)
      expect(result.error).toContain('Invalid issuer')
    })

    it('validates audience claim with string', async () => {
      const now = Math.floor(Date.now() / 1000)
      const token = await createTestJWT(
        {
          sub: 'user-123',
          aud: 'wrong-audience',
          exp: now + 3600,
          iat: now,
        },
        rsaKeyPair.privateKey
      )

      const result = await verifyJWT(token, {
        publicKey: rsaKeyPair.publicKey,
        audience: 'expected-audience',
      })

      expect(result.valid).toBe(false)
      expect(result.error).toContain('Invalid audience')
    })

    it('validates audience claim with array in token', async () => {
      const now = Math.floor(Date.now() / 1000)
      const token = await createTestJWT(
        {
          sub: 'user-123',
          aud: ['api-1', 'api-2'],
          exp: now + 3600,
          iat: now,
        },
        rsaKeyPair.privateKey
      )

      const result = await verifyJWT(token, {
        publicKey: rsaKeyPair.publicKey,
        audience: 'api-1',
      })

      expect(result.valid).toBe(true)
    })

    it('validates audience claim with array in options', async () => {
      const now = Math.floor(Date.now() / 1000)
      const token = await createTestJWT(
        {
          sub: 'user-123',
          aud: 'api-2',
          exp: now + 3600,
          iat: now,
        },
        rsaKeyPair.privateKey
      )

      const result = await verifyJWT(token, {
        publicKey: rsaKeyPair.publicKey,
        audience: ['api-1', 'api-2', 'api-3'],
      })

      expect(result.valid).toBe(true)
    })

    it('rejects when audience does not match any expected', async () => {
      const now = Math.floor(Date.now() / 1000)
      const token = await createTestJWT(
        {
          sub: 'user-123',
          aud: 'api-other',
          exp: now + 3600,
          iat: now,
        },
        rsaKeyPair.privateKey
      )

      const result = await verifyJWT(token, {
        publicKey: rsaKeyPair.publicKey,
        audience: ['api-1', 'api-2'],
      })

      expect(result.valid).toBe(false)
      expect(result.error).toContain('Invalid audience')
    })
  })

  describe('verifyJWT with JWKS', () => {
    it('fetches keys from JWKS URL', async () => {
      const now = Math.floor(Date.now() / 1000)
      const token = await createTestJWT(
        {
          sub: 'user-123',
          exp: now + 3600,
          iat: now,
        },
        rsaKeyPair.privateKey,
        { alg: 'RS256', kid: 'test-key-1' }
      )

      // Export public key as JWK for mock JWKS
      const publicJWK = await crypto.subtle.exportKey('jwk', rsaKeyPair.publicKey)

      // Mock fetch for JWKS
      vi.spyOn(global, 'fetch').mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          keys: [
            {
              ...publicJWK,
              kid: 'test-key-1',
              use: 'sig',
              alg: 'RS256',
            },
          ],
        }),
      } as Response)

      const result = await verifyJWT(token, {
        jwksUrl: 'https://issuer.com/.well-known/jwks.json',
      })

      expect(result.valid).toBe(true)
      expect(result.payload?.sub).toBe('user-123')
    })

    it('handles JWKS fetch failure', async () => {
      const token = await createTestJWT(
        { sub: 'user-123' },
        rsaKeyPair.privateKey,
        { alg: 'RS256', kid: 'test-key' }
      )

      vi.spyOn(global, 'fetch').mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
      } as Response)

      const result = await verifyJWT(token, {
        jwksUrl: 'https://issuer.com/.well-known/jwks.json',
      })

      expect(result.valid).toBe(false)
      expect(result.error).toContain('Failed to fetch JWKS')
    })

    it('handles missing key in JWKS', async () => {
      const token = await createTestJWT(
        { sub: 'user-123' },
        rsaKeyPair.privateKey,
        { alg: 'RS256', kid: 'non-existent-key' }
      )

      vi.spyOn(global, 'fetch').mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          keys: [
            {
              kty: 'RSA',
              kid: 'different-key',
              n: 'test',
              e: 'AQAB',
            },
          ],
        }),
      } as Response)

      const result = await verifyJWT(token, {
        jwksUrl: 'https://issuer.com/.well-known/jwks.json',
      })

      expect(result.valid).toBe(false)
      expect(result.error).toContain('No matching key found')
    })

    it('caches JWKS keys', async () => {
      const now = Math.floor(Date.now() / 1000)
      const token = await createTestJWT(
        { sub: 'user-123', exp: now + 3600, iat: now },
        rsaKeyPair.privateKey,
        { alg: 'RS256', kid: 'cached-key' }
      )

      const publicJWK = await crypto.subtle.exportKey('jwk', rsaKeyPair.publicKey)

      const fetchMock = vi.spyOn(global, 'fetch').mockResolvedValue({
        ok: true,
        json: async () => ({
          keys: [{ ...publicJWK, kid: 'cached-key', use: 'sig', alg: 'RS256' }],
        }),
      } as Response)

      // First verification
      await verifyJWT(token, {
        jwksUrl: 'https://issuer.com/.well-known/jwks.json',
      })

      // Second verification - should use cache
      await verifyJWT(token, {
        jwksUrl: 'https://issuer.com/.well-known/jwks.json',
      })

      // Fetch should only be called once
      expect(fetchMock).toHaveBeenCalledTimes(1)
    })
  })

  describe('verifyJWT with ES256', () => {
    it('verifies a valid ES256 token', async () => {
      const ecKeyPair = await generateECKeyPair()
      const now = Math.floor(Date.now() / 1000)

      const token = await createES256JWT(
        {
          sub: 'user-123',
          exp: now + 3600,
          iat: now,
        },
        ecKeyPair.privateKey
      )

      const result = await verifyJWT(token, {
        publicKey: ecKeyPair.publicKey,
      })

      expect(result.valid).toBe(true)
      expect(result.payload?.sub).toBe('user-123')
      expect(result.header?.alg).toBe('ES256')
    })
  })

  describe('decodeJWT', () => {
    it('decodes a valid JWT without verification', async () => {
      const token = await createTestJWT(
        { sub: 'user-123', custom: 'claim' },
        rsaKeyPair.privateKey
      )

      const decoded = decodeJWT(token)

      expect(decoded).not.toBeNull()
      expect(decoded?.header.alg).toBe('RS256')
      expect(decoded?.payload.sub).toBe('user-123')
      expect(decoded?.payload.custom).toBe('claim')
    })

    it('returns null for invalid JWT format', () => {
      expect(decodeJWT('invalid')).toBeNull()
      expect(decodeJWT('only.two')).toBeNull()
      expect(decodeJWT('')).toBeNull()
    })

    it('returns null for invalid base64 content', () => {
      expect(decodeJWT('!!!.!!!.!!!')).toBeNull()
    })
  })

  describe('isJWTExpired', () => {
    it('returns true for expired token', async () => {
      const now = Math.floor(Date.now() / 1000)
      const token = await createTestJWT(
        { sub: 'user-123', exp: now - 3600 },
        rsaKeyPair.privateKey
      )

      expect(isJWTExpired(token)).toBe(true)
    })

    it('returns false for valid token', async () => {
      const now = Math.floor(Date.now() / 1000)
      const token = await createTestJWT(
        { sub: 'user-123', exp: now + 3600 },
        rsaKeyPair.privateKey
      )

      expect(isJWTExpired(token)).toBe(false)
    })

    it('returns false for token without exp', async () => {
      const token = await createTestJWT(
        { sub: 'user-123' },
        rsaKeyPair.privateKey
      )

      expect(isJWTExpired(token)).toBe(false)
    })

    it('respects clock tolerance', async () => {
      const now = Math.floor(Date.now() / 1000)
      const token = await createTestJWT(
        { sub: 'user-123', exp: now - 30 }, // Expired 30 seconds ago
        rsaKeyPair.privateKey
      )

      expect(isJWTExpired(token, 0)).toBe(true)
      expect(isJWTExpired(token, 60)).toBe(false) // 60 second tolerance
    })

    it('returns false for invalid token', () => {
      expect(isJWTExpired('invalid-token')).toBe(false)
    })
  })

  describe('clearJWKSCache', () => {
    it('clears the JWKS cache', async () => {
      const now = Math.floor(Date.now() / 1000)
      const token = await createTestJWT(
        { sub: 'user-123', exp: now + 3600, iat: now },
        rsaKeyPair.privateKey,
        { alg: 'RS256', kid: 'cache-test-key' }
      )

      const publicJWK = await crypto.subtle.exportKey('jwk', rsaKeyPair.publicKey)

      const fetchMock = vi.spyOn(global, 'fetch').mockResolvedValue({
        ok: true,
        json: async () => ({
          keys: [{ ...publicJWK, kid: 'cache-test-key', use: 'sig', alg: 'RS256' }],
        }),
      } as Response)

      // First verification
      await verifyJWT(token, { jwksUrl: 'https://issuer.com/jwks' })
      expect(fetchMock).toHaveBeenCalledTimes(1)

      // Clear cache
      clearJWKSCache()

      // Second verification should fetch again
      await verifyJWT(token, { jwksUrl: 'https://issuer.com/jwks' })
      expect(fetchMock).toHaveBeenCalledTimes(2)
    })
  })
})
