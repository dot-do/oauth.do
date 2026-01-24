import { describe, it, expect, vi, beforeEach } from 'vitest'
import { Hono } from 'hono'
import {
  sessionAuth,
  requireSession,
  createOAuthRoutes,
  setSessionCookie,
  clearSessionCookie,
  getSessionFromCookie,
} from '../src/session-hono'
import { encodeSession } from '../src/session'
import type { SessionData } from '../src/session'

const TEST_SECRET = 'test-secret-for-hono-tests'

function createTestApp() {
  const app = new Hono()
  app.use('*', sessionAuth({ config: { secret: TEST_SECRET } }))
  app.get('/test', (c) => {
    return c.json({
      session: c.var.session,
      user: c.var.sessionUser,
    })
  })
  return app
}

async function createSessionCookie(session: SessionData): Promise<string> {
  return encodeSession(session, TEST_SECRET)
}

describe('sessionAuth middleware', () => {
  const validSession: SessionData = {
    userId: 'user_123',
    accessToken: 'tok_abc',
    email: 'alice@example.com',
    name: 'Alice',
  }

  it('sets null when no cookie present', async () => {
    const app = createTestApp()
    const res = await app.request('/test')
    const body = await res.json()

    expect(body.session).toBeNull()
    expect(body.user).toBeNull()
  })

  it('populates session from valid cookie', async () => {
    const app = createTestApp()
    const cookie = await createSessionCookie(validSession)
    const res = await app.request('/test', {
      headers: { Cookie: `session=${cookie}` },
    })
    const body = await res.json()

    expect(body.session.userId).toBe('user_123')
    expect(body.session.email).toBe('alice@example.com')
    expect(body.user.id).toBe('user_123')
    expect(body.user.email).toBe('alice@example.com')
    expect(body.user.name).toBe('Alice')
  })

  it('sets null for invalid cookie', async () => {
    const app = createTestApp()
    const res = await app.request('/test', {
      headers: { Cookie: 'session=invalid-data' },
    })
    const body = await res.json()

    expect(body.session).toBeNull()
    expect(body.user).toBeNull()
  })

  it('uses custom cookie name from config', async () => {
    const app = new Hono()
    app.use('*', sessionAuth({ config: { secret: TEST_SECRET, cookieName: 'my_auth' } }))
    app.get('/test', (c) => c.json({ session: c.var.session }))

    const cookie = await createSessionCookie(validSession)
    const res = await app.request('/test', {
      headers: { Cookie: `my_auth=${cookie}` },
    })
    const body = await res.json()
    expect(body.session.userId).toBe('user_123')
  })
})

describe('requireSession middleware', () => {
  const validSession: SessionData = {
    userId: 'user_123',
    accessToken: 'tok_abc',
  }

  it('returns 401 when no session', async () => {
    const app = new Hono()
    app.use('*', requireSession({ config: { secret: TEST_SECRET } }))
    app.get('/protected', (c) => c.json({ ok: true }))

    const res = await app.request('/protected')
    expect(res.status).toBe(401)
    const body = await res.json()
    expect(body.error).toBe('Unauthorized')
  })

  it('allows access with valid session', async () => {
    const app = new Hono()
    app.use('*', requireSession({ config: { secret: TEST_SECRET } }))
    app.get('/protected', (c) => c.json({ user: c.var.sessionUser }))

    const cookie = await createSessionCookie(validSession)
    const res = await app.request('/protected', {
      headers: { Cookie: `session=${cookie}` },
    })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.user.id).toBe('user_123')
  })

  it('returns 401 for expired session', async () => {
    const app = new Hono()
    app.use('*', requireSession({ config: { secret: TEST_SECRET } }))
    app.get('/protected', (c) => c.json({ ok: true }))

    const expiredSession: SessionData = {
      ...validSession,
      expiresAt: Date.now() - 1000, // expired
    }
    const cookie = await createSessionCookie(expiredSession)
    const res = await app.request('/protected', {
      headers: { Cookie: `session=${cookie}` },
    })
    expect(res.status).toBe(401)
    const body = await res.json()
    expect(body.message).toBe('Session expired')
  })
})

describe('createOAuthRoutes', () => {
  it('creates a Hono app with auth routes', () => {
    const routes = createOAuthRoutes()
    expect(routes).toBeInstanceOf(Hono)
  })

  describe('GET /login', () => {
    it('returns 500 if WORKOS_API_KEY not configured', async () => {
      const routes = createOAuthRoutes()
      const app = new Hono()
      app.route('/auth', routes)

      const res = await app.request('/auth/login')
      expect(res.status).toBe(500)
      const body = await res.json()
      expect(body.message).toContain('WORKOS_API_KEY')
    })

    it('returns 500 if WORKOS_CLIENT_ID not configured', async () => {
      const routes = createOAuthRoutes({ workosApiKey: 'sk_test_123' })
      const app = new Hono()
      app.route('/auth', routes)

      const res = await app.request('/auth/login')
      expect(res.status).toBe(500)
      const body = await res.json()
      expect(body.message).toContain('WORKOS_CLIENT_ID')
    })

    it('redirects to WorkOS authorization URL', async () => {
      const routes = createOAuthRoutes({
        workosApiKey: 'sk_test_123',
        clientId: 'client_test',
        redirectBaseUrl: 'https://app.example.com',
      })
      const app = new Hono()
      app.route('/auth', routes)

      const res = await app.request('/auth/login', { redirect: 'manual' })
      expect(res.status).toBe(302)
      const location = res.headers.get('location')!
      expect(location).toContain('api.workos.com/sso/authorize')
      expect(location).toContain('client_id=client_test')
      expect(location).toContain('redirect_uri=https%3A%2F%2Fapp.example.com%2Fauth%2Fcallback')
    })

    it('includes provider in authorization URL', async () => {
      const routes = createOAuthRoutes({
        workosApiKey: 'sk_test_123',
        clientId: 'client_test',
        redirectBaseUrl: 'https://app.example.com',
      })
      const app = new Hono()
      app.route('/auth', routes)

      const res = await app.request('/auth/login?provider=GoogleOAuth', { redirect: 'manual' })
      const location = res.headers.get('location')!
      expect(location).toContain('provider=GoogleOAuth')
    })
  })

  describe('GET /callback', () => {
    it('returns 400 for OAuth errors', async () => {
      const routes = createOAuthRoutes({
        workosApiKey: 'sk_test',
        clientId: 'client_test',
      })
      const app = new Hono()
      app.route('/auth', routes)

      const res = await app.request('/auth/callback?error=access_denied&error_description=User+cancelled')
      expect(res.status).toBe(400)
      const body = await res.json()
      expect(body.message).toContain('User cancelled')
    })

    it('returns 400 for missing code', async () => {
      const routes = createOAuthRoutes({
        workosApiKey: 'sk_test',
        clientId: 'client_test',
      })
      const app = new Hono()
      app.route('/auth', routes)

      const res = await app.request('/auth/callback')
      expect(res.status).toBe(400)
      const body = await res.json()
      expect(body.error).toBe('Missing authorization code')
    })
  })

  describe('GET /logout', () => {
    it('redirects to / by default', async () => {
      const routes = createOAuthRoutes()
      const app = new Hono()
      app.route('/auth', routes)

      const res = await app.request('/auth/logout', { redirect: 'manual' })
      expect(res.status).toBe(302)
      expect(res.headers.get('location')).toBe('/')
    })

    it('redirects to specified URL', async () => {
      const routes = createOAuthRoutes()
      const app = new Hono()
      app.route('/auth', routes)

      const res = await app.request('/auth/logout?redirect_uri=/login', { redirect: 'manual' })
      expect(res.status).toBe(302)
      expect(res.headers.get('location')).toBe('/login')
    })

    it('prevents open redirects', async () => {
      const routes = createOAuthRoutes()
      const app = new Hono()
      app.route('/auth', routes)

      const res = await app.request('/auth/logout?redirect_uri=https://evil.com', { redirect: 'manual' })
      expect(res.status).toBe(302)
      expect(res.headers.get('location')).toBe('/')
    })

    it('calls onLogout callback', async () => {
      const onLogout = vi.fn()
      const routes = createOAuthRoutes({ onLogout })
      const app = new Hono()
      app.route('/auth', routes)

      await app.request('/auth/logout', { redirect: 'manual' })
      expect(onLogout).toHaveBeenCalled()
    })
  })

  describe('POST /logout', () => {
    it('returns JSON success response', async () => {
      const routes = createOAuthRoutes()
      const app = new Hono()
      app.route('/auth', routes)

      const res = await app.request('/auth/logout', { method: 'POST' })
      expect(res.status).toBe(200)
      const body = await res.json()
      expect(body.success).toBe(true)
    })
  })

  describe('GET /me', () => {
    it('returns 401 when not authenticated', async () => {
      const routes = createOAuthRoutes({
        session: { secret: TEST_SECRET },
      })
      const app = new Hono()
      app.route('/auth', routes)

      const res = await app.request('/auth/me')
      expect(res.status).toBe(401)
    })

    it('returns user info when authenticated', async () => {
      const routes = createOAuthRoutes({
        session: { secret: TEST_SECRET },
      })
      const app = new Hono()
      app.route('/auth', routes)

      const session: SessionData = {
        userId: 'user_abc',
        accessToken: 'tok_123',
        email: 'bob@example.com',
        name: 'Bob',
        organizationId: 'org_xyz',
      }
      const cookie = await createSessionCookie(session)

      const res = await app.request('/auth/me', {
        headers: { Cookie: `session=${cookie}` },
      })
      expect(res.status).toBe(200)
      const body = await res.json()
      expect(body.id).toBe('user_abc')
      expect(body.email).toBe('bob@example.com')
      expect(body.name).toBe('Bob')
      expect(body.organizationId).toBe('org_xyz')
    })

    it('returns 401 for expired session', async () => {
      const routes = createOAuthRoutes({
        session: { secret: TEST_SECRET },
      })
      const app = new Hono()
      app.route('/auth', routes)

      const session: SessionData = {
        userId: 'user_abc',
        accessToken: 'tok_123',
        expiresAt: Date.now() - 1000,
      }
      const cookie = await createSessionCookie(session)

      const res = await app.request('/auth/me', {
        headers: { Cookie: `session=${cookie}` },
      })
      expect(res.status).toBe(401)
    })
  })

  describe('POST /refresh', () => {
    it('returns 500 if WORKOS_API_KEY not configured', async () => {
      const routes = createOAuthRoutes({
        session: { secret: TEST_SECRET },
      })
      const app = new Hono()
      app.route('/auth', routes)

      const session: SessionData = {
        userId: 'user_abc',
        accessToken: 'tok_123',
        refreshToken: 'ref_123',
      }
      const cookie = await createSessionCookie(session)

      const res = await app.request('/auth/refresh', {
        method: 'POST',
        headers: { Cookie: `session=${cookie}` },
      })
      expect(res.status).toBe(500)
    })

    it('returns 401 if not authenticated', async () => {
      const routes = createOAuthRoutes({
        workosApiKey: 'sk_test',
        clientId: 'client_test',
        session: { secret: TEST_SECRET },
      })
      const app = new Hono()
      app.route('/auth', routes)

      const res = await app.request('/auth/refresh', { method: 'POST' })
      expect(res.status).toBe(401)
    })

    it('returns 400 if no refresh token', async () => {
      const routes = createOAuthRoutes({
        workosApiKey: 'sk_test',
        clientId: 'client_test',
        session: { secret: TEST_SECRET },
      })
      const app = new Hono()
      app.route('/auth', routes)

      const session: SessionData = {
        userId: 'user_abc',
        accessToken: 'tok_123',
        // no refreshToken
      }
      const cookie = await createSessionCookie(session)

      const res = await app.request('/auth/refresh', {
        method: 'POST',
        headers: { Cookie: `session=${cookie}` },
      })
      expect(res.status).toBe(400)
      const body = await res.json()
      expect(body.message).toContain('No refresh token')
    })
  })
})
