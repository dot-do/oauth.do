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
})
