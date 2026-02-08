/**
 * oauth.do/session-hono - Hono middleware for cookie-based session auth
 *
 * Provides session-based authentication as an alternative to JWT middleware.
 * Uses AES-GCM encrypted cookies for secure, stateless sessions.
 *
 * @example
 * ```ts
 * import { Hono } from 'hono'
 * import { sessionAuth, requireSession, createOAuthRoutes } from 'oauth.do/hono'
 *
 * const app = new Hono()
 * app.use('*', sessionAuth())
 * app.route('/auth', createOAuthRoutes({
 *   workosApiKey: env.WORKOS_API_KEY,
 *   clientId: env.WORKOS_CLIENT_ID,
 * }))
 * ```
 */

import type { Context, MiddlewareHandler } from 'hono'
import { Hono } from 'hono'
import { getCookie, setCookie, deleteCookie } from 'hono/cookie'
import type { SessionData, SessionConfig } from './session.js'
import { encodeSession, decodeSession, defaultSessionConfig, getSessionConfig } from './session.js'

/** Session config with optional secret (secret is derived at runtime if not provided) */
type PartialSessionConfig = Omit<SessionConfig, 'secret'> & { secret?: string }

// ─────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────

/**
 * User info extracted from session
 */
export interface SessionUser {
  id: string
  email?: string
  name?: string
  organizationId?: string
}

// Extend Hono context with session variables
declare module 'hono' {
  interface ContextVariableMap {
    session: SessionData | null
    sessionUser: SessionUser | null
  }
}

/**
 * Options for session auth middleware
 */
export interface SessionAuthOptions {
  /** Session configuration (cookie name, secret, etc.) */
  config?: Partial<SessionConfig>
}

/**
 * Options for creating OAuth routes
 */
export interface OAuthRoutesOptions {
  /** WorkOS API Key */
  workosApiKey?: string
  /** WorkOS Client ID */
  clientId?: string
  /** Session configuration */
  session?: Partial<SessionConfig>
  /** Base URL for OAuth redirects (derived from request if not set) */
  redirectBaseUrl?: string
  /** Path prefix for auth routes (default: '') */
  pathPrefix?: string
  /** Callback after successful login */
  onLogin?: (session: SessionData, c: Context) => void | Promise<void>
  /** Callback after logout */
  onLogout?: (c: Context) => void | Promise<void>
  /** Enable debug logging */
  debug?: boolean
}

/**
 * Environment bindings for session auth
 */
export interface SessionEnv {
  WORKOS_API_KEY?: string
  WORKOS_CLIENT_ID?: string
  SESSION_SECRET?: string
  SESSION_COOKIE_NAME?: string
  SESSION_COOKIE_MAX_AGE?: string
  SESSION_COOKIE_SECURE?: string
  SESSION_COOKIE_SAME_SITE?: string
  AUTH_REDIRECT_BASE_URL?: string
  DEBUG?: string
}

// ─────────────────────────────────────────────────────────────────
// Cookie Helpers
// ─────────────────────────────────────────────────────────────────

/**
 * Set session cookie with encrypted session data
 */
export async function setSessionCookie(
  c: Context,
  session: SessionData,
  config: PartialSessionConfig = defaultSessionConfig
): Promise<void> {
  const encoded = await encodeSession(session, config.secret)
  setCookie(c, config.cookieName, encoded, {
    path: '/',
    httpOnly: true,
    secure: config.cookieSecure,
    sameSite: config.cookieSameSite === 'none' ? 'None' : config.cookieSameSite === 'strict' ? 'Strict' : 'Lax',
    maxAge: config.cookieMaxAge,
  })
}

/**
 * Clear session cookie
 */
export function clearSessionCookie(c: Context, config: PartialSessionConfig = defaultSessionConfig): void {
  deleteCookie(c, config.cookieName, { path: '/' })
}

/**
 * Get session from cookie
 */
export async function getSessionFromCookie(
  c: Context,
  config: PartialSessionConfig = defaultSessionConfig
): Promise<SessionData | null> {
  const encoded = getCookie(c, config.cookieName)
  if (!encoded) return null
  return decodeSession(encoded, config.secret)
}

// ─────────────────────────────────────────────────────────────────
// Middleware
// ─────────────────────────────────────────────────────────────────

/**
 * Session auth middleware - populates c.var.session and c.var.sessionUser
 *
 * Non-blocking: sets null if no session exists. Use requireSession() for guarded access.
 *
 * @example
 * ```ts
 * app.use('*', sessionAuth())
 * app.get('/me', (c) => {
 *   if (!c.var.session) return c.json({ error: 'Not authenticated' }, 401)
 *   return c.json(c.var.sessionUser)
 * })
 * ```
 */
export function sessionAuth(options: SessionAuthOptions = {}): MiddlewareHandler {
  return async (c, next) => {
    const env = (c.env ?? {}) as SessionEnv
    const config = { ...getSessionConfig(env as Record<string, string | undefined>), ...options.config }

    const session = await getSessionFromCookie(c, config)

    // Transparently re-encrypt sessions that were decoded with the legacy KDF
    if (session && (session as Record<string, unknown>)._needsReEncrypt) {
      await setSessionCookie(c, session, config)
    }

    c.set('session', session)
    c.set('sessionUser', session ? {
      id: session.userId,
      email: session.email,
      name: session.name,
      organizationId: session.organizationId,
    } : null)

    await next()
  }
}

/**
 * Require session middleware - returns 401 if no valid session
 *
 * @example
 * ```ts
 * app.use('/api/*', requireSession())
 * ```
 */
export function requireSession(options: SessionAuthOptions = {}): MiddlewareHandler {
  return async (c, next) => {
    const env = (c.env ?? {}) as SessionEnv
    const config = { ...getSessionConfig(env as Record<string, string | undefined>), ...options.config }

    const session = await getSessionFromCookie(c, config)

    if (!session) {
      return c.json({ error: 'Unauthorized', message: 'Authentication required' }, 401)
    }

    // Check expiration
    if (session.expiresAt && Date.now() >= session.expiresAt) {
      clearSessionCookie(c, config)
      return c.json({ error: 'Unauthorized', message: 'Session expired' }, 401)
    }

    c.set('session', session)
    c.set('sessionUser', {
      id: session.userId,
      email: session.email,
      name: session.name,
      organizationId: session.organizationId,
    })

    await next()
  }
}

// ─────────────────────────────────────────────────────────────────
// State Parameter Signing (CSRF Protection)
// ─────────────────────────────────────────────────────────────────

/** TTL for state tokens: 10 minutes */
const STATE_TTL_MS = 10 * 60 * 1000

/**
 * Sign a state payload using HMAC-SHA-256 so the callback can verify it
 * was generated by this server (CSRF protection).
 *
 * Format: base64url({ payload, exp, sig })
 *   - payload: the original state data (e.g. { redirect: '/dashboard' })
 *   - exp: expiration timestamp (ms)
 *   - sig: HMAC-SHA-256 of (payload + exp) using the session secret
 */
async function signState(payload: Record<string, unknown>, secret: string): Promise<string> {
  const exp = Date.now() + STATE_TTL_MS
  const encoder = new TextEncoder()
  const message = JSON.stringify(payload) + ':' + exp

  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const sigBuf = await crypto.subtle.sign('HMAC', key, encoder.encode(message))
  const sig = btoa(String.fromCharCode(...new Uint8Array(sigBuf)))

  return btoa(JSON.stringify({ payload, exp, sig }))
}

/**
 * Verify and extract a signed state parameter.
 * Returns the original payload if valid, or null if tampered/expired.
 */
async function verifyState(state: string, secret: string): Promise<Record<string, unknown> | null> {
  try {
    const { payload, exp, sig } = JSON.parse(atob(state)) as {
      payload: Record<string, unknown>
      exp: number
      sig: string
    }

    // Check expiration
    if (typeof exp !== 'number' || Date.now() > exp) {
      return null
    }

    // Verify HMAC
    const encoder = new TextEncoder()
    const message = JSON.stringify(payload) + ':' + exp
    const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify'])
    const sigBytes = Uint8Array.from(atob(sig), (c) => c.charCodeAt(0))
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, encoder.encode(message))

    if (!valid) return null

    return payload
  } catch {
    return null
  }
}

// ─────────────────────────────────────────────────────────────────
// WorkOS Client
// ─────────────────────────────────────────────────────────────────

/**
 * Create a lightweight WorkOS client (fetch-based, no SDK dependency)
 */
function createWorkOSClient(apiKey: string) {
  const baseUrl = 'https://api.workos.com'

  return {
    getAuthorizationUrl(options: {
      clientId: string
      redirectUri: string
      state?: string
      provider?: string
    }): string {
      const params = new URLSearchParams({
        client_id: options.clientId,
        redirect_uri: options.redirectUri,
        response_type: 'code',
        ...(options.state && { state: options.state }),
        ...(options.provider && { provider: options.provider }),
      })
      return `https://api.workos.com/sso/authorize?${params.toString()}`
    },

    async authenticateWithCode(options: {
      clientId: string
      code: string
      redirectUri: string
    }): Promise<{
      access_token: string
      refresh_token?: string
      expires_in?: number
      user: {
        id: string
        email: string
        first_name?: string
        last_name?: string
        organization_id?: string
      }
    }> {
      const response = await fetch(`${baseUrl}/user_management/authenticate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': `Bearer ${apiKey}`,
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: options.clientId,
          code: options.code,
          redirect_uri: options.redirectUri,
        }).toString(),
      })

      if (!response.ok) {
        const error = await response.text()
        throw new Error(`WorkOS authentication failed: ${response.status} - ${error}`)
      }

      return response.json()
    },

    async refreshToken(options: {
      clientId: string
      refreshToken: string
    }): Promise<{
      access_token: string
      refresh_token?: string
      expires_in?: number
    }> {
      const response = await fetch(`${baseUrl}/user_management/authenticate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': `Bearer ${apiKey}`,
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          client_id: options.clientId,
          refresh_token: options.refreshToken,
        }).toString(),
      })

      if (!response.ok) {
        const error = await response.text()
        throw new Error(`Token refresh failed: ${response.status} - ${error}`)
      }

      return response.json()
    },
  }
}

// ─────────────────────────────────────────────────────────────────
// OAuth Routes Factory
// ─────────────────────────────────────────────────────────────────

/**
 * Create mountable OAuth routes for login, callback, logout, me, and refresh.
 *
 * @example
 * ```ts
 * import { Hono } from 'hono'
 * import { createOAuthRoutes } from 'oauth.do/hono'
 *
 * const app = new Hono()
 * app.route('/auth', createOAuthRoutes({
 *   workosApiKey: env.WORKOS_API_KEY,
 *   clientId: env.WORKOS_CLIENT_ID,
 *   session: { secret: env.SESSION_SECRET },
 * }))
 * ```
 *
 * Routes:
 * - GET /login - Redirect to WorkOS authorization
 * - GET /callback - Handle OAuth callback, set session cookie
 * - GET /logout - Clear cookie, redirect
 * - POST /logout - Clear cookie, JSON response
 * - GET /me - Return session user info
 * - POST /refresh - Refresh access token
 */
export function createOAuthRoutes(options: OAuthRoutesOptions = {}): Hono {
  const app = new Hono()

  // UTF-8 charset middleware
  app.use('*', async (c, next) => {
    await next()
    const contentType = c.res.headers.get('content-type')
    if (contentType?.includes('application/json') && !contentType.includes('charset')) {
      c.res.headers.set('content-type', 'application/json; charset=utf-8')
    }
  })

  /**
   * GET /login - Redirect to WorkOS authorization
   */
  app.get('/login', async (c) => {
    const env = (c.env ?? {}) as SessionEnv
    const apiKey = options.workosApiKey ?? env.WORKOS_API_KEY
    const clientId = options.clientId ?? env.WORKOS_CLIENT_ID
    const sessionConfig = { ...getSessionConfig(env as Record<string, string | undefined>), ...options.session }

    if (!apiKey) {
      return c.json({ error: 'Server configuration error', message: 'WORKOS_API_KEY not configured' }, 500)
    }
    if (!clientId) {
      return c.json({ error: 'Server configuration error', message: 'WORKOS_CLIENT_ID not configured' }, 500)
    }

    const workos = createWorkOSClient(apiKey)
    const url = new URL(c.req.url)
    const baseUrl = options.redirectBaseUrl ?? env.AUTH_REDIRECT_BASE_URL ?? `${url.protocol}//${url.host}`

    const intendedRedirect = c.req.query('redirect_uri') || '/'
    const provider = c.req.query('provider')
    const state = await signState({ redirect: intendedRedirect }, sessionConfig.secret)

    const authUrl = workos.getAuthorizationUrl({
      clientId,
      redirectUri: `${baseUrl}/auth/callback`,
      state,
      provider,
    })

    return c.redirect(authUrl)
  })

  /**
   * GET /callback - Handle OAuth callback
   */
  app.get('/callback', async (c) => {
    const env = (c.env ?? {}) as SessionEnv
    const apiKey = options.workosApiKey ?? env.WORKOS_API_KEY
    const clientId = options.clientId ?? env.WORKOS_CLIENT_ID
    const sessionConfig = { ...getSessionConfig(env as Record<string, string | undefined>), ...options.session }
    const debug = options.debug ?? env.DEBUG === 'true'

    if (!apiKey) {
      return c.json({ error: 'Server configuration error', message: 'WORKOS_API_KEY not configured' }, 500)
    }
    if (!clientId) {
      return c.json({ error: 'Server configuration error', message: 'WORKOS_CLIENT_ID not configured' }, 500)
    }

    const code = c.req.query('code')
    const stateParam = c.req.query('state')
    const error = c.req.query('error')
    const errorDescription = c.req.query('error_description')

    if (error) {
      if (debug) console.error('[Auth] OAuth error:', error, errorDescription)
      return c.json({ error: 'Authentication failed', message: errorDescription || error }, 400)
    }

    if (!code) {
      return c.json({ error: 'Missing authorization code' }, 400)
    }

    // Validate state parameter (CSRF protection)
    if (!stateParam) {
      return c.json({ error: 'Missing state parameter' }, 400)
    }

    const stateData = await verifyState(stateParam, sessionConfig.secret)
    if (!stateData) {
      if (debug) console.error('[Auth] State validation failed - possible CSRF attack')
      return c.json({ error: 'Invalid or expired state parameter' }, 400)
    }

    const workos = createWorkOSClient(apiKey)
    const url = new URL(c.req.url)
    const baseUrl = options.redirectBaseUrl ?? env.AUTH_REDIRECT_BASE_URL ?? `${url.protocol}//${url.host}`

    try {
      const result = await workos.authenticateWithCode({
        clientId,
        code,
        redirectUri: `${baseUrl}/auth/callback`,
      })

      const session: SessionData = {
        userId: result.user.id,
        organizationId: result.user.organization_id,
        email: result.user.email,
        name: [result.user.first_name, result.user.last_name].filter(Boolean).join(' ') || undefined,
        accessToken: result.access_token,
        refreshToken: result.refresh_token,
        expiresAt: result.expires_in ? Date.now() + result.expires_in * 1000 : undefined,
      }

      await setSessionCookie(c, session, sessionConfig)
      await options.onLogin?.(session, c)

      let redirectTo = (stateData.redirect as string) || '/'

      // Prevent open redirects
      if (!redirectTo.startsWith('/')) {
        redirectTo = '/'
      }

      return c.redirect(redirectTo)
    } catch (err) {
      if (debug) console.error('[Auth] OAuth callback error:', err)
      return c.json({
        error: 'Authentication failed',
        message: err instanceof Error ? err.message : 'Unknown error',
      }, 500)
    }
  })

  /**
   * GET /logout - Clear session and redirect
   */
  app.get('/logout', async (c) => {
    const env = (c.env ?? {}) as SessionEnv
    const sessionConfig = { ...getSessionConfig(env as Record<string, string | undefined>), ...options.session }

    clearSessionCookie(c, sessionConfig)
    await options.onLogout?.(c)

    const redirectTo = c.req.query('redirect_uri') || '/'
    if (!redirectTo.startsWith('/')) {
      return c.redirect('/')
    }
    return c.redirect(redirectTo)
  })

  /**
   * POST /logout - JSON response logout
   */
  app.post('/logout', async (c) => {
    const env = (c.env ?? {}) as SessionEnv
    const sessionConfig = { ...getSessionConfig(env as Record<string, string | undefined>), ...options.session }

    clearSessionCookie(c, sessionConfig)
    await options.onLogout?.(c)

    return c.json({ success: true, message: 'Logged out successfully' })
  })

  /**
   * GET /me - Return session user info
   */
  app.get('/me', async (c) => {
    const env = (c.env ?? {}) as SessionEnv
    const sessionConfig = { ...getSessionConfig(env as Record<string, string | undefined>), ...options.session }

    const session = await getSessionFromCookie(c, sessionConfig)

    if (!session) {
      return c.json({ error: 'Unauthorized', message: 'Not authenticated' }, 401)
    }

    if (session.expiresAt && Date.now() >= session.expiresAt) {
      clearSessionCookie(c, sessionConfig)
      return c.json({ error: 'Unauthorized', message: 'Session expired' }, 401)
    }

    return c.json({
      id: session.userId,
      email: session.email,
      name: session.name,
      organizationId: session.organizationId,
    })
  })

  /**
   * POST /refresh - Refresh access token
   */
  app.post('/refresh', async (c) => {
    const env = (c.env ?? {}) as SessionEnv
    const apiKey = options.workosApiKey ?? env.WORKOS_API_KEY
    const clientId = options.clientId ?? env.WORKOS_CLIENT_ID
    const sessionConfig = { ...getSessionConfig(env as Record<string, string | undefined>), ...options.session }
    const debug = options.debug ?? env.DEBUG === 'true'

    if (!apiKey) {
      return c.json({ error: 'Server configuration error', message: 'WORKOS_API_KEY not configured' }, 500)
    }
    if (!clientId) {
      return c.json({ error: 'Server configuration error', message: 'WORKOS_CLIENT_ID not configured' }, 500)
    }

    const session = await getSessionFromCookie(c, sessionConfig)

    if (!session) {
      return c.json({ error: 'Unauthorized', message: 'Not authenticated' }, 401)
    }

    if (!session.refreshToken) {
      return c.json({ error: 'Cannot refresh', message: 'No refresh token available' }, 400)
    }

    const workos = createWorkOSClient(apiKey)

    try {
      const result = await workos.refreshToken({
        clientId,
        refreshToken: session.refreshToken,
      })

      const updatedSession: SessionData = {
        ...session,
        accessToken: result.access_token,
        refreshToken: result.refresh_token || session.refreshToken,
        expiresAt: result.expires_in ? Date.now() + result.expires_in * 1000 : undefined,
      }

      await setSessionCookie(c, updatedSession, sessionConfig)

      return c.json({ success: true, expiresAt: updatedSession.expiresAt })
    } catch (err) {
      if (debug) console.error('[Auth] Token refresh error:', err)
      clearSessionCookie(c, sessionConfig)
      return c.json({
        error: 'Refresh failed',
        message: err instanceof Error ? err.message : 'Unknown error',
      }, 401)
    }
  })

  return app
}
