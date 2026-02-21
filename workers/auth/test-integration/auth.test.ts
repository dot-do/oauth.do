/**
 * Auth Worker Integration Tests
 *
 * Runs the auth worker in miniflare (workerd) with real outbound calls.
 * No mocks — tests actual JWT verification via JWKS, admin token verification,
 * Cache API caching, and API key validation against live WorkOS.
 *
 * Requires `.dev.vars` with ADMIN_TOKEN (and optionally WORKOS_API_KEY).
 */
import { SELF, env } from 'cloudflare:test'
import { describe, it, expect } from 'vitest'

describe('Auth Worker', () => {
  // ─── Health ────────────────────────────────────────────────────────────
  describe('GET /health', () => {
    it('returns ok', async () => {
      const res = await SELF.fetch('https://auth.oauth.do/health')
      expect(res.status).toBe(200)
      const body = await res.json<{ status: string; service: string }>()
      expect(body.status).toBe('ok')
      expect(body.service).toBe('auth')
    })
  })

  // ─── Admin Token ───────────────────────────────────────────────────────
  describe('Admin Token Verification', () => {
    it('verifies valid admin token via GET /verify', async () => {
      const res = await SELF.fetch('https://auth.oauth.do/verify', {
        headers: { Authorization: `Bearer ${env.ADMIN_TOKEN}` },
      })
      expect(res.status).toBe(200)
      const body = await res.json<{ valid: boolean; user?: { id: string; roles?: string[] } }>()
      expect(body.valid).toBe(true)
      expect(body.user?.id).toBe('admin')
      expect(body.user?.roles).toContain('admin')
    })

    it('verifies valid admin token via POST /verify', async () => {
      const res = await SELF.fetch('https://auth.oauth.do/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: env.ADMIN_TOKEN }),
      })
      expect(res.status).toBe(200)
      const body = await res.json<{ valid: boolean }>()
      expect(body.valid).toBe(true)
    })

    it('rejects invalid admin token', async () => {
      const res = await SELF.fetch('https://auth.oauth.do/verify', {
        headers: { Authorization: 'Bearer wrong_token_value' },
      })
      expect(res.status).toBe(200)
      const body = await res.json<{ valid: boolean; error?: string }>()
      expect(body.valid).toBe(false)
    })

    it('returns admin user from GET /me', async () => {
      const res = await SELF.fetch('https://auth.oauth.do/me', {
        headers: { Authorization: `Bearer ${env.ADMIN_TOKEN}` },
      })
      expect(res.status).toBe(200)
      const user = await res.json<{ id: string; email?: string; permissions?: string[] }>()
      expect(user.id).toBe('admin')
      expect(user.permissions).toContain('*')
    })
  })

  // ─── JWT Verification (WorkOS JWKS) ───────────────────────────────────
  describe('JWT Verification', () => {
    it('rejects expired JWT', async () => {
      // A clearly expired JWT (exp in the past)
      const expiredJwt = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxMDAwMDAwMDAwfQ.fake'
      const res = await SELF.fetch('https://auth.oauth.do/verify', {
        headers: { Authorization: `Bearer ${expiredJwt}` },
      })
      const body = await res.json<{ valid: boolean; error?: string }>()
      expect(body.valid).toBe(false)
      expect(body.error).toBeDefined()
    })

    it('rejects malformed JWT', async () => {
      const res = await SELF.fetch('https://auth.oauth.do/verify', {
        headers: { Authorization: 'Bearer not.a.valid.jwt.at.all' },
      })
      const body = await res.json<{ valid: boolean }>()
      expect(body.valid).toBe(false)
    })
  })

  // ─── API Key Verification ─────────────────────────────────────────────
  describe('API Key Verification', () => {
    it('rejects non-sk_ tokens as invalid format', async () => {
      const res = await SELF.fetch('https://auth.oauth.do/verify?token=not_an_api_key')
      const body = await res.json<{ valid: boolean; error?: string }>()
      expect(body.valid).toBe(false)
    })

    it('rejects invalid sk_ key', async () => {
      // Without OAUTH binding, falls back to direct WorkOS API call
      const res = await SELF.fetch('https://auth.oauth.do/verify?token=sk_invalid_key_12345')
      const body = await res.json<{ valid: boolean; error?: string }>()
      expect(body.valid).toBe(false)
      // sk_ prefix is valid format, so error should NOT be a format error
      expect(body.error).not.toContain('Invalid API key format')
    })
  })

  // ─── Edge Cases ────────────────────────────────────────────────────────
  describe('Edge Cases', () => {
    it('returns 400 for missing token on GET /verify', async () => {
      const res = await SELF.fetch('https://auth.oauth.do/verify')
      expect(res.status).toBe(400)
      const body = await res.json<{ valid: boolean; error?: string }>()
      expect(body.valid).toBe(false)
      expect(body.error).toBe('Token required')
    })

    it('returns 401 for GET /me without auth', async () => {
      const res = await SELF.fetch('https://auth.oauth.do/me')
      expect(res.status).toBe(401)
    })

    it('caches results (second call should be cached)', async () => {
      // First call — uncached
      const res1 = await SELF.fetch('https://auth.oauth.do/verify', {
        headers: { Authorization: `Bearer ${env.ADMIN_TOKEN}` },
      })
      const body1 = await res1.json<{ valid: boolean; cached?: boolean }>()
      expect(body1.valid).toBe(true)

      // Second call — should be cached
      const res2 = await SELF.fetch('https://auth.oauth.do/verify', {
        headers: { Authorization: `Bearer ${env.ADMIN_TOKEN}` },
      })
      const body2 = await res2.json<{ valid: boolean; cached?: boolean }>()
      expect(body2.valid).toBe(true)
      expect(body2.cached).toBe(true)
    })
  })

  // ─── POST /verify (JSON body) ────────────────────────────────────────
  describe('POST /verify', () => {
    it('verifies token from JSON body', async () => {
      const res = await SELF.fetch('https://auth.oauth.do/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: env.ADMIN_TOKEN }),
      })
      expect(res.status).toBe(200)
      const body = await res.json<{ valid: boolean; user?: { id: string } }>()
      expect(body.valid).toBe(true)
      expect(body.user?.id).toBe('admin')
    })
  })

  // ─── Cache Invalidation ────────────────────────────────────────────────
  describe('POST /invalidate', () => {
    it('requires authentication', async () => {
      const res = await SELF.fetch('https://auth.oauth.do/invalidate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: 'some_token' }),
      })
      expect(res.status).toBe(401)
    })

    it('invalidates cached token', async () => {
      // First verify to populate cache
      await SELF.fetch('https://auth.oauth.do/verify', {
        headers: { Authorization: `Bearer ${env.ADMIN_TOKEN}` },
      })

      // Invalidate
      const res = await SELF.fetch('https://auth.oauth.do/invalidate', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${env.ADMIN_TOKEN}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ token: env.ADMIN_TOKEN }),
      })
      expect(res.status).toBe(200)
      const body = await res.json<{ invalidated: boolean }>()
      expect(body.invalidated).toBe(true)

      // Next verify should NOT be cached
      const res2 = await SELF.fetch('https://auth.oauth.do/verify', {
        headers: { Authorization: `Bearer ${env.ADMIN_TOKEN}` },
      })
      const body2 = await res2.json<{ valid: boolean; cached?: boolean }>()
      expect(body2.valid).toBe(true)
      expect(body2.cached).toBeFalsy()
    })
  })
})
