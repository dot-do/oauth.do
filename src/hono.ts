/**
 * oauth.do/hono - Hono middleware for authentication
 *
 * Lightweight authentication middleware for Cloudflare Workers.
 * Uses jose for JWT verification - no heavy WorkOS SDK dependency.
 *
 * @packageDocumentation
 */

import type { Context, MiddlewareHandler } from 'hono'
import { getCookie } from 'hono/cookie'
import type { JWTPayload } from 'jose'
import * as jose from 'jose'

// Cloudflare Workers Cache API type
declare const caches: {
  default: Cache
}

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════

export interface AuthUser {
  id: string
  email?: string
  name?: string
  organizationId?: string
  roles?: string[]
  permissions?: string[]
  metadata?: Record<string, unknown>
}

export interface AuthVariables {
  user: AuthUser | null
  userId: string | null
  isAuth: boolean
  token: string | null
}

declare module 'hono' {
  interface ContextVariableMap extends AuthVariables {}
}

export interface AuthOptions {
  /** Cookie name for JWT token (default: 'auth') */
  cookieName?: string
  /** Header name for Bearer token (default: 'Authorization') */
  headerName?: string
  /** WorkOS Client ID for JWT audience verification */
  clientId?: string
  /** JWKS URI for token verification (required) */
  jwksUri: string
  /** Skip auth for certain paths */
  skip?: (c: Context) => boolean
  /** Cache duration for JWKS in seconds (default: 3600) */
  jwksCacheTtl?: number
}

export interface RequireAuthOptions extends AuthOptions {
  /** Redirect to login page instead of 401 */
  redirectTo?: string
  /** Required roles (any of) */
  roles?: string[]
  /** Required permissions (all of) */
  permissions?: string[]
}

export interface ApiKeyOptions {
  /** Header name (default: 'X-API-Key') */
  headerName?: string
  /** Verify function - return user if valid, null if not */
  verify: (key: string, c: Context) => Promise<AuthUser | null>
}

// ═══════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════

const TOKEN_CACHE_TTL = 5 * 60 // 5 minutes
const CACHE_URL_PREFIX = 'https://oauth.do/_cache/token/'

// ═══════════════════════════════════════════════════════════════════════════
// JWT Utilities
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Hash a token for cache key (avoids storing raw tokens in cache)
 */
async function hashToken(token: string): Promise<string> {
  const data = new TextEncoder().encode(token)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * Get cached user from Cache API
 */
async function getCachedUser(token: string): Promise<AuthUser | null> {
  try {
    const cache = caches.default
    const hash = await hashToken(token)
    const cacheKey = new Request(`${CACHE_URL_PREFIX}${hash}`)
    const cached = await cache.match(cacheKey)

    if (!cached) return null

    const data = await cached.json() as { user: AuthUser; expiresAt: number }
    if (data.expiresAt < Date.now()) return null

    return data.user
  } catch {
    return null
  }
}

/**
 * Cache user in Cache API
 */
async function cacheUser(token: string, user: AuthUser): Promise<void> {
  try {
    const cache = caches.default
    const hash = await hashToken(token)
    const cacheKey = new Request(`${CACHE_URL_PREFIX}${hash}`)
    const data = { user, expiresAt: Date.now() + TOKEN_CACHE_TTL * 1000 }
    const response = new Response(JSON.stringify(data), {
      headers: { 'Cache-Control': `max-age=${TOKEN_CACHE_TTL}` },
    })
    await cache.put(cacheKey, response)
  } catch {
    // Cache failures are non-fatal
  }
}

/**
 * Extract JWT from request (cookie or Bearer header)
 */
function extractToken(c: Context, cookieName: string, headerName: string): string | null {
  // Try Bearer header first
  const authHeader = c.req.header(headerName)
  if (authHeader?.startsWith('Bearer ')) {
    return authHeader.slice(7)
  }

  // Try cookie
  const cookie = getCookie(c, cookieName)
  if (cookie) return cookie

  return null
}

/**
 * Convert JWT payload to AuthUser
 */
function payloadToUser(payload: JWTPayload): AuthUser {
  return {
    id: payload.sub || '',
    email: payload.email as string | undefined,
    name: payload.name as string | undefined,
    organizationId: payload.org_id as string | undefined,
    roles: payload.roles as string[] | undefined,
    permissions: payload.permissions as string[] | undefined,
    metadata: payload.metadata as Record<string, unknown> | undefined,
  }
}

// JWKS cache (module-level, persists across requests)
let jwksCache: jose.JWTVerifyGetKey | null = null
let jwksCacheExpiry = 0

/**
 * Get JWKS verifier with caching
 */
async function getJwks(jwksUri: string, cacheTtl: number): Promise<jose.JWTVerifyGetKey> {
  const now = Date.now()
  if (jwksCache && jwksCacheExpiry > now) {
    return jwksCache
  }

  jwksCache = jose.createRemoteJWKSet(new URL(jwksUri))
  jwksCacheExpiry = now + cacheTtl * 1000
  return jwksCache
}

// ═══════════════════════════════════════════════════════════════════════════
// Middleware
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Auth middleware - populates c.var.user if authenticated
 *
 * Does NOT reject unauthenticated requests. Use requireAuth() for that.
 *
 * @example
 * ```ts
 * import { Hono } from 'hono'
 * import { auth } from 'oauth.do/hono'
 *
 * const app = new Hono()
 * app.use('*', auth({ jwksUri: 'https://api.workos.com/sso/jwks/client_xxx' }))
 *
 * app.get('/api/me', (c) => {
 *   if (!c.var.user) return c.json({ error: 'Not authenticated' }, 401)
 *   return c.json(c.var.user)
 * })
 * ```
 */
export function auth(options: AuthOptions): MiddlewareHandler {
  const {
    cookieName = 'auth',
    headerName = 'Authorization',
    clientId,
    jwksUri,
    skip,
    jwksCacheTtl = 3600,
  } = options

  if (!jwksUri) {
    throw new Error('oauth.do auth() middleware requires a "jwksUri" option. Example: auth({ jwksUri: "https://api.workos.com/sso/jwks/<your-client-id>" })')
  }

  return async (c, next) => {
    // Initialize variables
    c.set('user', null)
    c.set('userId', null)
    c.set('isAuth', false)
    c.set('token', null)

    // Skip if configured
    if (skip?.(c)) {
      return next()
    }

    const token = extractToken(c, cookieName, headerName)
    if (!token) {
      return next()
    }

    c.set('token', token)

    // Check cache first
    const cached = await getCachedUser(token)
    if (cached) {
      c.set('user', cached)
      c.set('userId', cached.id)
      c.set('isAuth', true)
      return next()
    }

    // Verify JWT
    try {
      const jwks = await getJwks(jwksUri, jwksCacheTtl)
      const { payload } = await jose.jwtVerify(token, jwks, {
        audience: clientId,
      })

      const user = payloadToUser(payload)
      c.set('user', user)
      c.set('userId', user.id)
      c.set('isAuth', true)

      // Cache the result
      await cacheUser(token, user)
    } catch {
      // Invalid token - leave user as null
    }

    return next()
  }
}

/**
 * Require auth middleware - rejects unauthenticated requests
 *
 * @example
 * ```ts
 * import { Hono } from 'hono'
 * import { auth, requireAuth } from 'oauth.do/hono'
 *
 * const app = new Hono()
 * app.use('*', auth({ jwksUri: 'https://api.workos.com/sso/jwks/client_xxx' }))
 * app.use('/api/*', requireAuth({ jwksUri: 'https://api.workos.com/sso/jwks/client_xxx' }))
 *
 * app.get('/api/secret', (c) => {
 *   return c.json({ secret: 'data', user: c.var.user })
 * })
 * ```
 */
export function requireAuth(options: RequireAuthOptions): MiddlewareHandler {
  const { redirectTo, roles, permissions, ...authOptions } = options

  return async (c, next) => {
    // Run auth middleware first if not already done
    if (c.var.user === undefined) {
      await auth(authOptions)(c, async () => {})
    }

    if (!c.var.isAuth || !c.var.user) {
      if (redirectTo) {
        return c.redirect(redirectTo)
      }
      return c.json({ error: 'Authentication required' }, 401)
    }

    // Check roles (any of)
    if (roles?.length) {
      const userRoles = c.var.user.roles || []
      const hasRole = roles.some((r) => userRoles.includes(r))
      if (!hasRole) {
        return c.json({ error: 'Insufficient permissions' }, 403)
      }
    }

    // Check permissions (all of)
    if (permissions?.length) {
      const userPerms = c.var.user.permissions || []
      const hasAllPerms = permissions.every((p) => userPerms.includes(p))
      if (!hasAllPerms) {
        return c.json({ error: 'Insufficient permissions' }, 403)
      }
    }

    return next()
  }
}

/**
 * API key middleware - authenticates via API key header
 *
 * @example
 * ```ts
 * import { Hono } from 'hono'
 * import { apiKey } from 'oauth.do/hono'
 *
 * const app = new Hono()
 * app.use('/api/*', apiKey({
 *   verify: async (key, c) => {
 *     // Verify key against your database/service
 *     const user = await verifyApiKey(key)
 *     return user
 *   }
 * }))
 * ```
 */
export function apiKey(options: ApiKeyOptions): MiddlewareHandler {
  const { headerName = 'X-API-Key', verify } = options

  return async (c, next) => {
    c.set('user', null)
    c.set('userId', null)
    c.set('isAuth', false)
    c.set('token', null)

    const key = c.req.header(headerName)
    if (!key) {
      return c.json({ error: 'API key required' }, 401)
    }

    const user = await verify(key, c)
    if (!user) {
      return c.json({ error: 'Invalid API key' }, 401)
    }

    c.set('user', user)
    c.set('userId', user.id)
    c.set('isAuth', true)
    c.set('token', key)

    return next()
  }
}

/**
 * Combined auth middleware - tries JWT first, then API key
 *
 * @example
 * ```ts
 * import { Hono } from 'hono'
 * import { combined } from 'oauth.do/hono'
 *
 * const app = new Hono()
 * app.use('/api/*', combined({
 *   apiKey: {
 *     verify: async (key) => verifyApiKey(key)
 *   }
 * }))
 * ```
 */
// ═══════════════════════════════════════════════════════════════════════════
// Session Auth Re-exports
// ═══════════════════════════════════════════════════════════════════════════

export { sessionAuth, requireSession, createOAuthRoutes } from './session-hono'
export type { SessionUser, SessionAuthOptions, OAuthRoutesOptions, SessionEnv } from './session-hono'
export { encodeSession, decodeSession, getSessionConfig } from './session'
export type { SessionData, SessionConfig } from './session'

// ═══════════════════════════════════════════════════════════════════════════
// Combined Auth
// ═══════════════════════════════════════════════════════════════════════════

export function combined(options: {
  auth?: AuthOptions
  apiKey?: ApiKeyOptions
}): MiddlewareHandler {
  return async (c, next) => {
    // Try JWT auth first
    if (options.auth) {
      await auth(options.auth)(c, async () => {})
      if (c.var.isAuth) {
        return next()
      }
    }

    // Fall back to API key
    if (options.apiKey) {
      const key = c.req.header(options.apiKey.headerName || 'X-API-Key')
      if (key) {
        const user = await options.apiKey.verify(key, c)
        if (user) {
          c.set('user', user)
          c.set('userId', user.id)
          c.set('isAuth', true)
          c.set('token', key)
          return next()
        }
      }
    }

    return c.json({ error: 'Authentication required' }, 401)
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Browser Detection & Smart Auth Helpers
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Detect if request is from a browser (vs API client like curl, SDK, etc)
 */
export function isBrowser(c: Context): boolean {
  const accept = c.req.header('Accept') || ''
  const userAgent = c.req.header('User-Agent') || ''

  // Check Accept header - browsers typically accept text/html
  if (accept.includes('text/html')) return true

  // Check for common browser user agents
  const browserPatterns = [
    /Mozilla/i,
    /Chrome/i,
    /Safari/i,
    /Firefox/i,
    /Edge/i,
    /Opera/i,
  ]

  // Exclude known API clients
  const apiClientPatterns = [
    /curl/i,
    /wget/i,
    /httpie/i,
    /postman/i,
    /insomnia/i,
    /axios/i,
    /node-fetch/i,
    /got/i,
    /undici/i,
  ]

  const isApiClient = apiClientPatterns.some((p) => p.test(userAgent))
  if (isApiClient) return false

  return browserPatterns.some((p) => p.test(userAgent))
}

/**
 * Return auth error response - redirect for browsers, JSON for API clients
 */
function authErrorResponse(c: Context, options: {
  loginUrl?: string
  message?: string
}): Response {
  const { loginUrl = 'https://oauth.do/login', message = 'Authentication required' } = options

  if (isBrowser(c)) {
    // Redirect browsers to login with return URL
    const returnUrl = encodeURIComponent(c.req.url)
    return c.redirect(`${loginUrl}?return_to=${returnUrl}`)
  }

  // Return JSON for API clients with helpful info
  return c.json({
    error: message,
    code: 'UNAUTHORIZED',
    help: {
      message: 'Authenticate using one of these methods:',
      methods: {
        bearer: {
          header: 'Authorization: Bearer <token>',
          description: 'JWT token from oauth.do',
          getToken: 'https://oauth.do/docs/tokens',
        },
        apiKey: {
          header: 'X-API-Key: <key>',
          description: 'API key for programmatic access',
          getKey: 'https://oauth.do/settings/api-keys',
        },
        cookie: {
          description: 'Session cookie from browser login',
          login: loginUrl,
        },
      },
    },
  }, 401)
}

/**
 * Return forbidden response - for insufficient permissions
 */
function forbiddenResponse(c: Context, options: {
  message?: string
  required?: { roles?: string[]; permissions?: string[] }
}): Response {
  const { message = 'Insufficient permissions', required } = options

  return c.json({
    error: message,
    code: 'FORBIDDEN',
    ...(required && { required }),
  }, 403)
}

export interface AssertAuthOptions extends AuthOptions {
  /** Login URL for browser redirects (default: https://oauth.do/login) */
  loginUrl?: string
  /** API key verification function */
  apiKey?: ApiKeyOptions
  /** Skip auth for certain paths */
  skip?: (c: Context) => boolean
}

/**
 * Assert authentication - smart handling for browsers vs API clients
 *
 * - Browsers: Redirect to login page
 * - API clients: Return 401 JSON with instructions on how to authenticate
 *
 * Supports: Cookie, Bearer JWT, X-API-Key
 *
 * @example
 * ```ts
 * import { Hono } from 'hono'
 * import { assertAuth } from 'oauth.do/hono'
 *
 * const app = new Hono()
 *
 * // Protect all routes except public ones
 * app.use('/*', assertAuth({
 *   skip: (c) => c.req.path === '/' || c.req.path === '/health',
 * }))
 *
 * app.get('/api/me', (c) => c.json(c.var.user))
 * ```
 */
export function assertAuth(options: AssertAuthOptions): MiddlewareHandler {
  const { loginUrl = 'https://oauth.do/login', apiKey: apiKeyOptions, skip, ...authOptions } = options

  return async (c, next) => {
    // Skip if configured
    if (skip?.(c)) {
      return next()
    }

    // Try JWT auth (cookie or bearer header)
    await auth(authOptions)(c, async () => {})
    if (c.var.isAuth) {
      return next()
    }

    // Try API key
    if (apiKeyOptions) {
      const key = c.req.header(apiKeyOptions.headerName || 'X-API-Key')
      if (key) {
        const user = await apiKeyOptions.verify(key, c)
        if (user) {
          c.set('user', user)
          c.set('userId', user.id)
          c.set('isAuth', true)
          c.set('token', key)
          return next()
        }
      }
    }

    // Not authenticated - return appropriate response
    return authErrorResponse(c, { loginUrl })
  }
}

export interface AssertRoleOptions extends AssertAuthOptions {
  /** Required roles (user must have at least one) */
  roles: string[]
}

/**
 * Assert user has one of the required roles
 *
 * @example
 * ```ts
 * app.use('/admin/*', assertRole({ roles: ['admin', 'superadmin'] }))
 * ```
 */
export function assertRole(options: AssertRoleOptions): MiddlewareHandler {
  const { roles, ...authOptions } = options

  return async (c, next) => {
    // First ensure authenticated
    const authMiddleware = assertAuth(authOptions)
    const authResult = await authMiddleware(c, async () => {})

    // If auth middleware returned a response, return it
    if (authResult) return authResult

    // Check if user is authenticated after middleware ran
    if (!c.var.isAuth || !c.var.user) {
      return authErrorResponse(c, { loginUrl: authOptions.loginUrl })
    }

    // Check roles
    const userRoles = c.var.user.roles || []
    const hasRole = roles.some((r) => userRoles.includes(r))

    if (!hasRole) {
      return forbiddenResponse(c, {
        message: 'Insufficient permissions - required role not found',
        required: { roles },
      })
    }

    return next()
  }
}

/**
 * Assert user is an admin (has 'admin' or 'superadmin' role)
 *
 * @example
 * ```ts
 * app.use('/admin/*', assertAdmin())
 * ```
 */
export function assertAdmin(options: AssertAuthOptions): MiddlewareHandler {
  return assertRole({ ...options, roles: ['admin', 'superadmin'] })
}

export interface AssertPermissionOptions extends AssertAuthOptions {
  /** Required permissions (user must have all) */
  permissions: string[]
}

/**
 * Assert user has all required permissions
 *
 * @example
 * ```ts
 * app.use('/api/users/*', assertPermission({ permissions: ['users:read', 'users:write'] }))
 * ```
 */
export function assertPermission(options: AssertPermissionOptions): MiddlewareHandler {
  const { permissions, ...authOptions } = options

  return async (c, next) => {
    // First ensure authenticated
    const authMiddleware = assertAuth(authOptions)
    const authResult = await authMiddleware(c, async () => {})

    if (authResult) return authResult

    if (!c.var.isAuth || !c.var.user) {
      return authErrorResponse(c, { loginUrl: authOptions.loginUrl })
    }

    // Check permissions (must have all)
    const userPerms = c.var.user.permissions || []
    const hasAllPerms = permissions.every((p) => userPerms.includes(p))

    if (!hasAllPerms) {
      return forbiddenResponse(c, {
        message: 'Insufficient permissions',
        required: { permissions },
      })
    }

    return next()
  }
}
