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
  /** WorkOS Client ID (default: oauth.do client ID) */
  clientId?: string
  /** JWKS URI for token verification (default: WorkOS JWKS) */
  jwksUri?: string
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

const OAUTH_DO_CONFIG = {
  clientId: 'client_01JQYTRXK9ZPD8JPJTKDCRB656',
  jwksUri: 'https://api.workos.com/sso/jwks/client_01JQYTRXK9ZPD8JPJTKDCRB656',
}

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
 * app.use('*', auth())
 *
 * app.get('/api/me', (c) => {
 *   if (!c.var.user) return c.json({ error: 'Not authenticated' }, 401)
 *   return c.json(c.var.user)
 * })
 * ```
 */
export function auth(options: AuthOptions = {}): MiddlewareHandler {
  const {
    cookieName = 'auth',
    headerName = 'Authorization',
    clientId = OAUTH_DO_CONFIG.clientId,
    jwksUri = OAUTH_DO_CONFIG.jwksUri,
    skip,
    jwksCacheTtl = 3600,
  } = options

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
 * app.use('*', auth())
 * app.use('/api/*', requireAuth())
 *
 * app.get('/api/secret', (c) => {
 *   return c.json({ secret: 'data', user: c.var.user })
 * })
 * ```
 */
export function requireAuth(options: RequireAuthOptions = {}): MiddlewareHandler {
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
