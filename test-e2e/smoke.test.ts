import { describe, it, expect } from 'vitest'
import { OAUTH_DO_CLI_CLIENT_ID } from 'id.org.ai/auth'

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

  describe('Device auth endpoint', () => {
    it('returns device code and verification URI for oauth_do_cli', async () => {
      const res = await fetch(`${ID_ORG_AI}/oauth/device`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: OAUTH_DO_CLI_CLIENT_ID,
          scope: 'openid profile email',
        }).toString(),
      })

      expect(res.status).toBe(200)

      const data = await res.json() as Record<string, unknown>
      expect(data.device_code).toBeDefined()
      expect(typeof data.device_code).toBe('string')
      expect(data.user_code).toBeDefined()
      expect(typeof data.user_code).toBe('string')
      expect(data.verification_uri).toBeDefined()
      expect(typeof data.verification_uri).toBe('string')
      expect(data.verification_uri_complete).toBeDefined()
      expect(data.expires_in).toBeDefined()
      expect(typeof data.expires_in).toBe('number')
      expect(data.interval).toBeDefined()
      expect(typeof data.interval).toBe('number')
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
