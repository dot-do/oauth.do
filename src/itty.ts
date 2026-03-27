/**
 * oauth.do/itty - itty-router middleware for authentication
 *
 * Lightweight authentication middleware for Cloudflare Workers using itty-router.
 * Uses jose for JWT verification against id.org.ai JWKS.
 *
 * @packageDocumentation
 */

import * as jose from 'jose'
import { getCachedUser, cacheUser, payloadToUser, getJwks } from './auth-shared.js'

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════

export { type AuthUser } from "./types.js";
import type { AuthUser } from "./types.js";
export interface AuthContext {
  user: AuthUser | null
  userId: string | null
  isAuth: boolean
  token: string | null
}

/**
 * Extended request type with auth context
 */
export interface AuthRequest extends Request {
  auth: AuthContext
}

/**
 * Environment bindings with auth context
 */
export interface AuthEnv {
  auth?: AuthContext
  [key: string]: unknown
}

export interface AuthOptions {
  /** Cookie name for JWT token (default: 'auth') */
  cookieName?: string
  /** Header name for Bearer token (default: 'Authorization') */
  headerName?: string
  /** Client ID for JWT audience verification (optional) */
  clientId?: string
  /** JWKS URI for token verification (default: id.org.ai JWKS) */
  jwksUri?: string
  /** Skip auth for certain paths */
  skip?: (request: Request) => boolean
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
  verify: (key: string, request: Request) => Promise<AuthUser | null>
}

// ═══════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════

const DEFAULT_CLIENT_ID = 'client_01JQYTRXK9ZPD8JPJTKDCRB656'

function getDefaultConfig() {
  const clientId = (typeof process !== 'undefined' && process.env?.OAUTH_CLIENT_ID) || DEFAULT_CLIENT_ID
  return {
    clientId,
    jwksUri: 'https://id.org.ai/.well-known/jwks.json',
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// JWT Utilities
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Parse cookies from request
 */
function parseCookies(request: Request): Record<string, string> {
  const cookieHeader = request.headers.get('Cookie')
  if (!cookieHeader) return {}

  const cookies: Record<string, string> = {}
  for (const pair of cookieHeader.split(';')) {
    const [name, ...rest] = pair.trim().split('=')
    if (name && rest.length > 0) {
      cookies[name] = rest.join('=')
    }
  }
  return cookies
}

/**
 * Extract JWT from request (cookie or Bearer header)
 */
function extractToken(request: Request, cookieName: string, headerName: string): string | null {
  // Try Bearer header first
  const authHeader = request.headers.get(headerName)
  if (authHeader?.startsWith('Bearer ')) {
    return authHeader.slice(7)
  }

  // Try cookie
  const cookies = parseCookies(request)
  const cookie = cookies[cookieName]
  if (cookie) return cookie

  return null
}


/**
 * Create default auth context
 */
function createDefaultAuthContext(): AuthContext {
  return {
    user: null,
    userId: null,
    isAuth: false,
    token: null,
  }
}

/**
 * JSON error response helper
 */
function jsonError(message: string, status: number): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

// ═══════════════════════════════════════════════════════════════════════════
// Middleware
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Optional auth middleware - populates request.auth if authenticated
 *
 * Does NOT reject unauthenticated requests. Use requireAuth() for that.
 *
 * @example
 * ```ts
 * import { Router } from 'itty-router'
 * import { optionalAuth } from 'oauth.do/itty'
 *
 * const router = Router()
 * router.all('*', optionalAuth())
 *
 * router.get('/api/me', (request) => {
 *   if (!request.auth.user) {
 *     return new Response(JSON.stringify({ error: 'Not authenticated' }), { status: 401 })
 *   }
 *   return new Response(JSON.stringify(request.auth.user))
 * })
 * ```
 */
export function optionalAuth(options: AuthOptions = {}) {
  const defaults = getDefaultConfig()
  const {
    cookieName = 'auth',
    headerName = 'Authorization',
    clientId = defaults.clientId,
    jwksUri = defaults.jwksUri,
    skip,
    jwksCacheTtl = 3600,
  } = options

  return async (request: Request): Promise<void> => {
    // Initialize auth context on request
    const authRequest = request as AuthRequest
    authRequest.auth = createDefaultAuthContext()

    // Skip if configured
    if (skip?.(request)) {
      return
    }

    const token = extractToken(request, cookieName, headerName)
    if (!token) {
      return
    }

    authRequest.auth.token = token

    // Check cache first
    const cached = await getCachedUser(token)
    if (cached) {
      authRequest.auth.user = cached
      authRequest.auth.userId = cached.id
      authRequest.auth.isAuth = true
      return
    }

    // Verify JWT
    try {
      const jwks = await getJwks(jwksUri, jwksCacheTtl)
      const { payload } = await jose.jwtVerify(token, jwks, {
        audience: clientId,
      })

      const user = payloadToUser(payload)
      authRequest.auth.user = user
      authRequest.auth.userId = user.id
      authRequest.auth.isAuth = true

      // Cache the result
      await cacheUser(token, user)
    } catch {
      // Invalid token - leave user as null
    }
  }
}

/**
 * Require auth middleware - rejects unauthenticated requests
 *
 * @example
 * ```ts
 * import { Router } from 'itty-router'
 * import { requireAuth } from 'oauth.do/itty'
 *
 * const router = Router()
 * router.get('/api/secret', requireAuth(), (request) => {
 *   return new Response(JSON.stringify({ secret: 'data', user: request.auth.user }))
 * })
 * ```
 */
export function requireAuth(options: RequireAuthOptions = {}) {
  const { redirectTo, roles, permissions, ...authOptions } = options

  return async (request: Request): Promise<Response | void> => {
    const authRequest = request as AuthRequest

    // Run optional auth first if not already done
    if (!authRequest.auth) {
      await optionalAuth(authOptions)(request)
    }

    if (!authRequest.auth.isAuth || !authRequest.auth.user) {
      if (redirectTo) {
        return Response.redirect(redirectTo, 302)
      }
      return jsonError('Authentication required', 401)
    }

    // Check roles (any of)
    if (roles?.length) {
      const userRoles = authRequest.auth.user.roles || []
      const hasRole = roles.some((r) => userRoles.includes(r))
      if (!hasRole) {
        return jsonError('Insufficient permissions', 403)
      }
    }

    // Check permissions (all of)
    if (permissions?.length) {
      const userPerms = authRequest.auth.user.permissions || []
      const hasAllPerms = permissions.every((p) => userPerms.includes(p))
      if (!hasAllPerms) {
        return jsonError('Insufficient permissions', 403)
      }
    }

    // Continue to next handler (return undefined)
  }
}

/**
 * API key middleware - authenticates via API key header
 *
 * @example
 * ```ts
 * import { Router } from 'itty-router'
 * import { apiKey } from 'oauth.do/itty'
 *
 * const router = Router()
 * router.use('/api/*', apiKey({
 *   verify: async (key, request) => {
 *     // Verify key against your database/service
 *     const user = await verifyApiKey(key)
 *     return user
 *   }
 * }))
 * ```
 */
export function apiKey(options: ApiKeyOptions) {
  const { headerName = 'X-API-Key', verify } = options

  return async (request: Request): Promise<Response | void> => {
    const authRequest = request as AuthRequest
    authRequest.auth = createDefaultAuthContext()

    const key = request.headers.get(headerName)
    if (!key) {
      return jsonError('API key required', 401)
    }

    const user = await verify(key, request)
    if (!user) {
      return jsonError('Invalid API key', 401)
    }

    authRequest.auth.user = user
    authRequest.auth.userId = user.id
    authRequest.auth.isAuth = true
    authRequest.auth.token = key
  }
}

/**
 * Combined auth middleware - tries JWT first, then API key
 *
 * @example
 * ```ts
 * import { Router } from 'itty-router'
 * import { combined } from 'oauth.do/itty'
 *
 * const router = Router()
 * router.all('/api/*', combined({
 *   apiKey: {
 *     verify: async (key) => verifyApiKey(key)
 *   }
 * }))
 * ```
 */
export function combined(options: { auth?: AuthOptions; apiKey?: ApiKeyOptions }) {
  return async (request: Request): Promise<Response | void> => {
    const authRequest = request as AuthRequest

    // Try JWT auth first
    if (options.auth) {
      await optionalAuth(options.auth)(request)
      if (authRequest.auth?.isAuth) {
        return
      }
    }

    // Fall back to API key
    if (options.apiKey) {
      const key = request.headers.get(options.apiKey.headerName || 'X-API-Key')
      if (key) {
        const user = await options.apiKey.verify(key, request)
        if (user) {
          if (!authRequest.auth) {
            authRequest.auth = createDefaultAuthContext()
          }
          authRequest.auth.user = user
          authRequest.auth.userId = user.id
          authRequest.auth.isAuth = true
          authRequest.auth.token = key
          return
        }
      }
    }

    return jsonError('Authentication required', 401)
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Utility exports
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Helper to get auth context from request
 */
export function getAuth(request: Request): AuthContext {
  return (request as AuthRequest).auth || createDefaultAuthContext()
}

/**
 * Helper to check if request is authenticated
 */
export function isAuthenticated(request: Request): boolean {
  return (request as AuthRequest).auth?.isAuth === true
}

/**
 * Helper to get user from request
 */
export function getUser(request: Request): AuthUser | null {
  return (request as AuthRequest).auth?.user || null
}
