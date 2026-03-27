import { describe, it, expect } from 'vitest'

const ID_ORG_AI = 'https://id.org.ai'

describe('oauth.do e2e smoke tests', () => {
  describe('JWKS endpoint', () => {
    it('returns valid JWKS with RSA signing keys', async () => {
      const res = await fetch(`${ID_ORG_AI}/.well-known/jwks.json`)
      expect(res.status).toBe(200)

      const jwks = await res.json() as { keys: Array<Record<string, string>> }
      expect(jwks.keys).toBeDefined()
      expect(jwks.keys.length).toBeGreaterThanOrEqual(1)

      for (const key of jwks.keys) {
        expect(key.kty).toBe('RSA')
        expect(key.use).toBe('sig')
        expect(key.alg).toBe('RS256')
        expect(key.kid).toBeDefined()
        expect(key.n).toBeDefined()
        expect(key.e).toBeDefined()
      }
    })
  })

  describe('JWT sign-verify roundtrip', () => {
    it('signs a JWT with id.org.ai SigningKeyManager and verifies via jose', async () => {
      const { SigningKeyManager, signAccessToken } = await import('id.org.ai/oauth')
      const jose = await import('jose')

      // Create a signing key manager with in-memory storage
      const store = new Map<string, unknown>()
      const storageOp = async (op: { op: string; key?: string; value?: unknown }) => {
        switch (op.op) {
          case 'get': return { value: store.get(op.key!) }
          case 'put': store.set(op.key!, op.value); return {}
          default: return {}
        }
      }

      const manager = new SigningKeyManager(storageOp)
      const key = await manager.getCurrentKey()

      // Sign a JWT with test claims
      const token = await signAccessToken(
        key,
        { sub: 'test-user', client_id: 'test-client', scope: 'openid profile' },
        { issuer: 'https://oauth.test', expiresIn: 3600 }
      )

      expect(token).toBeDefined()
      expect(token.split('.').length).toBe(3)

      // Verify through jose (same path middleware uses)
      const jwks = await manager.getJWKS()
      expect(jwks.keys.length).toBeGreaterThanOrEqual(1)

      // Import the public key and verify
      const publicKey = await crypto.subtle.importKey(
        'jwk',
        {
          kty: 'RSA',
          n: jwks.keys[0].n,
          e: jwks.keys[0].e,
          alg: 'RS256',
          use: 'sig',
        },
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        false,
        ['verify']
      )

      const { payload } = await jose.jwtVerify(token, publicKey, {
        issuer: 'https://oauth.test',
      })

      expect(payload.sub).toBe('test-user')
      expect(payload.client_id).toBe('test-client')
      expect(payload.scope).toBe('openid profile')
      expect(payload.iss).toBe('https://oauth.test')
      expect(payload.exp).toBeDefined()
      expect(payload.iat).toBeDefined()
    })
  })
})
