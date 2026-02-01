import { describe, it, expect, vi, beforeEach } from 'vitest'
import {
  generateSigningKey,
  serializeSigningKey,
  deserializeSigningKey,
  exportPublicKeyToJWKS,
  exportKeysToJWKS,
  signAccessToken,
  SigningKeyManager,
  type SigningKey,
  type SerializedSigningKey,
} from './jwt-signing.js'

// Helper: decode base64url string to bytes
function base64UrlDecode(s: string): Uint8Array {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice(0, (4 - (s.length % 4)) % 4)
  const binary = atob(padded)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

// Helper: decode JWT parts
function decodeJwt(token: string) {
  const [headerB64, payloadB64, signatureB64] = token.split('.')
  const header = JSON.parse(new TextDecoder().decode(base64UrlDecode(headerB64!)))
  const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64!)))
  return { header, payload, signatureB64: signatureB64!, headerB64: headerB64!, payloadB64: payloadB64! }
}

describe('SigningKey generation', () => {
  it('generateSigningKey creates a valid RSA-2048 key pair', async () => {
    const key = await generateSigningKey()
    expect(key.privateKey).toBeInstanceOf(CryptoKey)
    expect(key.publicKey).toBeInstanceOf(CryptoKey)
    expect(key.privateKey.algorithm).toMatchObject({ name: 'RSASSA-PKCS1-v1_5' })
    const algo = key.privateKey.algorithm as RsaHashedKeyAlgorithm
    expect(algo.modulusLength).toBe(2048)
  })

  it('generated key has correct algorithm RS256', async () => {
    const key = await generateSigningKey()
    expect(key.alg).toBe('RS256')
  })

  it('generated key has a kid', async () => {
    const key = await generateSigningKey()
    expect(key.kid).toMatch(/^oauth-do-key-/)
  })

  it('accepts a custom kid', async () => {
    const key = await generateSigningKey('my-custom-kid')
    expect(key.kid).toBe('my-custom-kid')
  })

  it('has a createdAt timestamp', async () => {
    const before = Date.now()
    const key = await generateSigningKey()
    const after = Date.now()
    expect(key.createdAt).toBeGreaterThanOrEqual(before)
    expect(key.createdAt).toBeLessThanOrEqual(after)
  })
})

describe('serializeSigningKey / deserializeSigningKey roundtrip', () => {
  it('preserves the key through serialization roundtrip', async () => {
    const original = await generateSigningKey('roundtrip-test')
    const serialized = await serializeSigningKey(original)
    const restored = await deserializeSigningKey(serialized)

    expect(restored.kid).toBe(original.kid)
    expect(restored.alg).toBe(original.alg)
    expect(restored.createdAt).toBe(original.createdAt)

    // Verify the restored key can sign and the original public key can verify
    const data = new TextEncoder().encode('test-data')
    const signature = await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, restored.privateKey, data)
    const valid = await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, original.publicKey, signature, data)
    expect(valid).toBe(true)
  })

  it('serialized format contains expected fields', async () => {
    const key = await generateSigningKey()
    const serialized = await serializeSigningKey(key)
    expect(serialized.kid).toBe(key.kid)
    expect(serialized.alg).toBe('RS256')
    expect(serialized.privateKeyJwk).toBeDefined()
    expect(serialized.publicKeyJwk).toBeDefined()
    expect(serialized.createdAt).toBe(key.createdAt)
  })
})

describe('exportPublicKeyToJWKS / toPublicJWK', () => {
  it('returns valid JWK with required RSA fields', async () => {
    const key = await generateSigningKey('jwk-test')
    const jwk = await exportPublicKeyToJWKS(key)

    expect(jwk.kty).toBe('RSA')
    expect(jwk.kid).toBe('jwk-test')
    expect(jwk.alg).toBe('RS256')
    expect(jwk.use).toBe('sig')
    expect(jwk.n).toBeDefined()
    expect(typeof jwk.n).toBe('string')
    expect(jwk.e).toBeDefined()
    expect(typeof jwk.e).toBe('string')
  })

  it('does NOT include private key components', async () => {
    const key = await generateSigningKey()
    const jwk = await exportPublicKeyToJWKS(key)
    const jwkAny = jwk as Record<string, unknown>

    expect(jwkAny.d).toBeUndefined()
    expect(jwkAny.p).toBeUndefined()
    expect(jwkAny.q).toBeUndefined()
    expect(jwkAny.dp).toBeUndefined()
    expect(jwkAny.dq).toBeUndefined()
    expect(jwkAny.qi).toBeUndefined()
  })
})

describe('exportKeysToJWKS', () => {
  it('returns a JWKS document with all keys', async () => {
    const key1 = await generateSigningKey('k1')
    const key2 = await generateSigningKey('k2')
    const jwks = await exportKeysToJWKS([key1, key2])

    expect(jwks.keys).toHaveLength(2)
    expect(jwks.keys[0]!.kid).toBe('k1')
    expect(jwks.keys[1]!.kid).toBe('k2')
  })
})

describe('signAccessToken', () => {
  let key: SigningKey

  beforeEach(async () => {
    key = await generateSigningKey('sign-test')
  })

  it('signs a valid JWT with correct claims', async () => {
    const token = await signAccessToken(
      key,
      { sub: 'user-123', client_id: 'client-abc', scope: 'read write' },
      { issuer: 'https://oauth.do', audience: 'https://api.example.com' }
    )

    const { header, payload } = decodeJwt(token)

    expect(header.alg).toBe('RS256')
    expect(header.typ).toBe('JWT')
    expect(header.kid).toBe('sign-test')

    expect(payload.sub).toBe('user-123')
    expect(payload.client_id).toBe('client-abc')
    expect(payload.scope).toBe('read write')
    expect(payload.iss).toBe('https://oauth.do')
    expect(payload.aud).toBe('https://api.example.com')
    expect(typeof payload.iat).toBe('number')
    expect(typeof payload.exp).toBe('number')
  })

  it('token is verifiable using the public key', async () => {
    const token = await signAccessToken(
      key,
      { sub: 'user-1', client_id: 'c1' },
      { issuer: 'https://oauth.do' }
    )

    const { headerB64, payloadB64, signatureB64 } = decodeJwt(token)
    const sigBytes = base64UrlDecode(signatureB64)
    const data = new TextEncoder().encode(`${headerB64}.${payloadB64}`)

    const valid = await crypto.subtle.verify(
      { name: 'RSASSA-PKCS1-v1_5' },
      key.publicKey,
      sigBytes,
      data
    )
    expect(valid).toBe(true)
  })

  it('respects custom expiresIn parameter', async () => {
    const token = await signAccessToken(
      key,
      { sub: 'u', client_id: 'c' },
      { issuer: 'https://oauth.do', expiresIn: 7200 }
    )

    const { payload } = decodeJwt(token)
    expect(payload.exp - payload.iat).toBe(7200)
  })

  it('default expiresIn is 3600', async () => {
    const token = await signAccessToken(
      key,
      { sub: 'u', client_id: 'c' },
      { issuer: 'https://oauth.do' }
    )

    const { payload } = decodeJwt(token)
    expect(payload.exp - payload.iat).toBe(3600)
  })

  it('includes additional claims when provided', async () => {
    const token = await signAccessToken(
      key,
      { sub: 'u', client_id: 'c', custom_claim: 'hello', org_id: 'org-1' },
      { issuer: 'https://oauth.do' }
    )

    const { payload } = decodeJwt(token)
    expect(payload.custom_claim).toBe('hello')
    expect(payload.org_id).toBe('org-1')
  })

  it('omits audience when not provided', async () => {
    const token = await signAccessToken(
      key,
      { sub: 'u', client_id: 'c' },
      { issuer: 'https://oauth.do' }
    )

    const { payload } = decodeJwt(token)
    expect(payload.aud).toBeUndefined()
  })
})

describe('SigningKeyManager', () => {
  it('initializes with a generated key when no keys exist', async () => {
    const manager = new SigningKeyManager()
    const key = await manager.getCurrentKey()

    expect(key).toBeDefined()
    expect(key.alg).toBe('RS256')
    expect(key.kid).toBeDefined()
  })

  it('getActiveKey returns the same key on subsequent calls', async () => {
    const manager = new SigningKeyManager()
    const key1 = await manager.getCurrentKey()
    const key2 = await manager.getCurrentKey()
    expect(key1.kid).toBe(key2.kid)
  })

  it('getAllKeys returns all keys', async () => {
    const manager = new SigningKeyManager({ maxKeys: 3 })
    await manager.getCurrentKey()
    await manager.rotateKey()

    const allKeys = manager.getAllKeys()
    expect(allKeys).toHaveLength(2)
  })

  it('toJWKS returns JWKs for all keys', async () => {
    const manager = new SigningKeyManager({ maxKeys: 3 })
    await manager.getCurrentKey()
    await manager.rotateKey()

    const jwks = await manager.toJWKS()
    expect(jwks.keys).toHaveLength(2)
    expect(jwks.keys[0]!.kty).toBe('RSA')
    expect(jwks.keys[1]!.kty).toBe('RSA')
  })

  it('rotateKey adds a new key and makes it active', async () => {
    const manager = new SigningKeyManager({ maxKeys: 3 })
    const original = await manager.getCurrentKey()
    const rotated = await manager.rotateKey()
    const current = await manager.getCurrentKey()

    expect(rotated.kid).toBe(current.kid)
    expect(rotated.kid).not.toBe(original.kid)
  })

  it('rotateKey respects maxKeys limit and removes oldest', async () => {
    const manager = new SigningKeyManager({ maxKeys: 2 })
    const first = await manager.getCurrentKey()
    await manager.rotateKey()
    await manager.rotateKey()

    const allKeys = manager.getAllKeys()
    expect(allKeys).toHaveLength(2)
    // The first key should have been removed
    expect(allKeys.find((k) => k.kid === first.kid)).toBeUndefined()
  })

  it('key persistence: exportKeys/loadKeys roundtrip works', async () => {
    const manager1 = new SigningKeyManager({ maxKeys: 3 })
    await manager1.getCurrentKey()
    await manager1.rotateKey()

    const exported = await manager1.exportKeys()
    expect(exported).toHaveLength(2)

    const manager2 = new SigningKeyManager({ maxKeys: 3 })
    await manager2.loadKeys(exported)

    const keys1 = manager1.getAllKeys()
    const keys2 = manager2.getAllKeys()
    expect(keys2).toHaveLength(2)
    expect(keys2[0]!.kid).toBe(keys1[0]!.kid)
    expect(keys2[1]!.kid).toBe(keys1[1]!.kid)

    // Verify the loaded key can sign and be verified by original public key
    const token = await manager2.signAccessToken(
      { sub: 'u', client_id: 'c' },
      { issuer: 'https://oauth.do' }
    )
    const { headerB64, payloadB64, signatureB64 } = decodeJwt(token)
    const sigBytes = base64UrlDecode(signatureB64)
    const data = new TextEncoder().encode(`${headerB64}.${payloadB64}`)

    const activeKey = await manager1.getCurrentKey()
    const valid = await crypto.subtle.verify(
      { name: 'RSASSA-PKCS1-v1_5' },
      activeKey.publicKey,
      sigBytes,
      data
    )
    expect(valid).toBe(true)
  })

  it('signAccessToken uses the current key', async () => {
    const manager = new SigningKeyManager()
    const token = await manager.signAccessToken(
      { sub: 'user-1', client_id: 'client-1' },
      { issuer: 'https://oauth.do' }
    )

    const { header } = decodeJwt(token)
    const currentKey = await manager.getCurrentKey()
    expect(header.kid).toBe(currentKey.kid)
  })

  it('default maxKeys is 2', async () => {
    const manager = new SigningKeyManager()
    await manager.getCurrentKey()
    await manager.rotateKey()
    await manager.rotateKey()

    expect(manager.getAllKeys()).toHaveLength(2)
  })
})
