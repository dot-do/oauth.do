/**
 * Auth Worker - Lightweight JWT/API key verification
 *
 * This worker is designed to be fast and lightweight.
 * It only uses jose for JWT verification - no heavy SDK dependencies.
 *
 * Features:
 * - JWT verification with JWKS (WorkOS)
 * - API key verification with hashing and caching
 * - Cookie-based session validation
 * - Cache API for token caching (5 min TTL)
 *
 * @module auth-worker
 */

import { Hono } from 'hono'
import { cors } from 'hono/cors'
import * as jose from 'jose'

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════

interface Env {
  WORKOS_CLIENT_ID: string
  WORKOS_API_KEY?: string
  ADMIN_TOKEN?: string
  ALLOWED_ORIGINS?: string
  // RPC binding to OAuth worker for API key verification
  OAUTH?: Fetcher
}

/**
 * Authenticated user from JWT or API key
 *
 * This is compatible with the canonical AuthUser in oauth.do/src/types.ts.
 * All fields are optional except id for maximum compatibility.
 */
interface AuthUser {
  /** Unique user identifier */
  id: string
  /** User's email address */
  email?: string
  /** User's display name */
  name?: string
  /** User's profile image URL */
  image?: string
  /** Organization/tenant ID (canonical name) */
  organizationId?: string
  /**
   * Organization/tenant ID (alias for backwards compatibility)
   * @deprecated Use organizationId instead
   */
  org?: string
  /** User roles for RBAC */
  roles?: string[]
  /** User permissions for fine-grained access */
  permissions?: string[]
  /** Additional user metadata */
  metadata?: Record<string, unknown>
}

interface VerifyResult {
  valid: boolean
  user?: AuthUser
  error?: string
  cached?: boolean
}

// ═══════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════

const TOKEN_CACHE_TTL = 5 * 60 // 5 minutes for valid tokens
const NEGATIVE_CACHE_TTL = 60 // 60 seconds for invalid tokens
const CACHE_URL_PREFIX = 'https://auth.oauth.do/_cache/'

// JWKS cache (module-level)
let jwksCache: jose.JWTVerifyGetKey | null = null
let jwksCacheExpiry = 0
const JWKS_CACHE_TTL = 60 * 60 * 1000 // 1 hour

// ═══════════════════════════════════════════════════════════════════════════
// Utilities
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Extract roles from JWT payload, handling both WorkOS 'role' (singular)
 * and 'roles' (array) claims
 */
function extractRoles(payload: jose.JWTPayload): string[] | undefined {
  const roles = payload.roles as string[] | undefined
  const role = payload.role as string | undefined
  if (roles && role && !roles.includes(role)) {
    return [...roles, role]
  }
  return roles ?? (role ? [role] : undefined)
}

async function hashToken(token: string): Promise<string> {
  const data = new TextEncoder().encode(token)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

async function getCachedResult(token: string): Promise<VerifyResult | null> {
  try {
    const cache = caches.default
    const hash = await hashToken(token)
    const cacheKey = new Request(`${CACHE_URL_PREFIX}${hash}`)
    const cached = await cache.match(cacheKey)

    if (!cached) return null

    const data = (await cached.json()) as { result: VerifyResult; expiresAt: number }
    if (data.expiresAt < Date.now()) return null

    return { ...data.result, cached: true }
  } catch {
    return null
  }
}

async function cacheResult(token: string, result: VerifyResult): Promise<void> {
  try {
    const cache = caches.default
    const hash = await hashToken(token)
    const cacheKey = new Request(`${CACHE_URL_PREFIX}${hash}`)
    // Use shorter TTL for invalid tokens to allow retry sooner
    const ttl = result.valid ? TOKEN_CACHE_TTL : NEGATIVE_CACHE_TTL
    const data = { result, expiresAt: Date.now() + ttl * 1000 }
    const response = new Response(JSON.stringify(data), {
      headers: { 'Cache-Control': `max-age=${ttl}` },
    })
    await cache.put(cacheKey, response)
  } catch {
    // Non-fatal
  }
}

// oauth.do JWKS cache (for tokens issued by oauth.do)
let oauthJwksCache: jose.JWTVerifyGetKey | null = null
let oauthJwksCacheExpiry = 0

async function getOAuthJwks(): Promise<jose.JWTVerifyGetKey> {
  const now = Date.now()
  if (oauthJwksCache && oauthJwksCacheExpiry > now) {
    return oauthJwksCache
  }

  const jwksUri = 'https://oauth.do/.well-known/jwks.json'
  oauthJwksCache = jose.createRemoteJWKSet(new URL(jwksUri))
  oauthJwksCacheExpiry = now + JWKS_CACHE_TTL
  return oauthJwksCache
}

// WorkOS JWKS cache (for tokens issued directly by WorkOS)
async function getWorkosJwks(clientId: string): Promise<jose.JWTVerifyGetKey> {
  const now = Date.now()
  if (jwksCache && jwksCacheExpiry > now) {
    return jwksCache
  }

  const jwksUri = `https://api.workos.com/sso/jwks/${clientId}`
  jwksCache = jose.createRemoteJWKSet(new URL(jwksUri))
  jwksCacheExpiry = now + JWKS_CACHE_TTL
  return jwksCache
}

// ═══════════════════════════════════════════════════════════════════════════
// Verification Functions
// ═══════════════════════════════════════════════════════════════════════════

async function verifyJWT(token: string, env: Env): Promise<VerifyResult> {
  // Try oauth.do JWKS first (tokens issued by oauth.do platform)
  // No audience/issuer constraint - oauth.do tokens may have various audiences
  // (e.g., 'first-party' for login flow, client_id for OAuth flow)
  // and various issuers (e.g., 'https://oauth.do', 'https://events.do' via X-Issuer)
  let oauthError: string | undefined
  try {
    const oauthJwks = await getOAuthJwks()
    const { payload } = await jose.jwtVerify(token, oauthJwks)

    const orgId = payload.org_id as string | undefined
    const user: AuthUser = {
      id: payload.sub || '',
      email: payload.email as string | undefined,
      name: payload.name as string | undefined,
      image: payload.picture as string | undefined,
      organizationId: orgId,
      org: orgId, // Backwards compatibility alias
      roles: extractRoles(payload),
      permissions: payload.permissions as string[] | undefined,
    }

    return { valid: true, user }
  } catch (err) {
    oauthError = err instanceof Error ? err.message : 'oauth.do JWKS verification failed'
  }

  // Try WorkOS JWKS (tokens issued directly by WorkOS)
  // WorkOS session tokens (from device flow) may not have an 'aud' claim,
  // so we verify without audience constraint first, then with audience as fallback
  try {
    const workosJwks = await getWorkosJwks(env.WORKOS_CLIENT_ID)
    const { payload } = await jose.jwtVerify(token, workosJwks)

    const workosOrgId = payload.org_id as string | undefined
    const user: AuthUser = {
      id: payload.sub || '',
      email: payload.email as string | undefined,
      name: payload.name as string | undefined,
      image: payload.picture as string | undefined,
      organizationId: workosOrgId,
      org: workosOrgId, // Backwards compatibility alias
      roles: extractRoles(payload),
      permissions: payload.permissions as string[] | undefined,
    }

    return { valid: true, user }
  } catch (err) {
    const workosError = err instanceof Error ? err.message : 'WorkOS JWKS verification failed'
    return { valid: false, error: `JWT verification failed (oauth.do: ${oauthError}, WorkOS: ${workosError})` }
  }
}

/**
 * Constant-time string comparison to prevent timing attacks.
 * Uses crypto.subtle.timingSafeEqual if available (Cloudflare Workers),
 * otherwise falls back to a manual constant-time implementation.
 */
function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  // Use native timingSafeEqual if available (Cloudflare Workers non-standard extension)
  // @ts-expect-error - timingSafeEqual is not in standard WebCrypto types
  if (typeof crypto?.subtle?.timingSafeEqual === 'function') {
    // @ts-expect-error - timingSafeEqual is not in standard WebCrypto types
    return crypto.subtle.timingSafeEqual(a, b)
  }

  // Fallback: manual constant-time comparison
  // This should only be used in test environments
  if (a.length !== b.length) return false
  let result = 0
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i]
  }
  return result === 0
}

async function verifyAdminToken(token: string, env: Env): Promise<VerifyResult> {
  if (!env.ADMIN_TOKEN) return { valid: false, error: 'Admin token not configured' }

  // Constant-time comparison to prevent timing attacks
  const tokenBytes = new TextEncoder().encode(token)
  const adminBytes = new TextEncoder().encode(env.ADMIN_TOKEN)

  // To avoid leaking length information, we compare against itself when lengths differ
  // This ensures the comparison takes the same time regardless of length mismatch
  const lengthsMatch = tokenBytes.length === adminBytes.length
  const compareBytes = lengthsMatch ? adminBytes : tokenBytes

  // timingSafeEqual requires equal-length buffers, so we compare:
  // - tokenBytes vs adminBytes when lengths match (actual comparison)
  // - tokenBytes vs tokenBytes when lengths differ (always true, but we'll return false)
  const isEqual = timingSafeEqual(tokenBytes, compareBytes)

  if (lengthsMatch && isEqual) {
    return {
      valid: true,
      user: {
        id: 'admin',
        email: 'admin@oauth.do',
        roles: ['admin'],
        permissions: ['*'],
      },
    }
  }

  return { valid: false, error: 'Invalid admin token' }
}

async function verifyApiKey(key: string, env: Env): Promise<VerifyResult> {
  // API keys start with sk_
  if (!key.startsWith('sk_')) {
    return { valid: false, error: 'Invalid API key format' }
  }

  // If we have an OAuth worker binding, use RPC to verify
  if (env.OAUTH) {
    try {
      const response = await env.OAUTH.fetch('http://oauth/verify-api-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key }),
      })
      return (await response.json()) as VerifyResult
    } catch {
      return { valid: false, error: 'API key verification service unavailable' }
    }
  }

  // Fallback: Call WorkOS API directly (slower, but works without OAuth worker)
  if (env.WORKOS_API_KEY) {
    try {
      const response = await fetch('https://api.workos.com/user_management/users/me', {
        headers: { Authorization: `Bearer ${key}` },
      })

      if (response.ok) {
        const data = (await response.json()) as { id: string; email: string; first_name?: string; last_name?: string }
        return {
          valid: true,
          user: {
            id: data.id,
            email: data.email,
            name: [data.first_name, data.last_name].filter(Boolean).join(' ') || undefined,
          },
        }
      }
    } catch {
      // Fall through
    }
  }

  return { valid: false, error: 'Invalid API key' }
}

// ═══════════════════════════════════════════════════════════════════════════
// Main Verification
// ═══════════════════════════════════════════════════════════════════════════

async function verifyToken(token: string, env: Env): Promise<VerifyResult> {
  // Check cache first
  const cached = await getCachedResult(token)
  if (cached) return cached

  let result: VerifyResult

  // Try different verification methods based on token format
  if (token.startsWith('sk_')) {
    // API keys always start with sk_
    result = await verifyApiKey(token, env)
  } else if (token.includes('.')) {
    // JWTs contain dots (header.payload.signature)
    result = await verifyJWT(token, env)
  } else if (env.ADMIN_TOKEN) {
    // For other tokens, try admin token verification if configured
    // This uses timing-safe comparison internally
    result = await verifyAdminToken(token, env)
  } else {
    // No admin token configured and not a recognized format
    result = { valid: false, error: 'Invalid token format' }
  }

  // Cache results (valid tokens: 5 min, invalid tokens: 60 sec)
  await cacheResult(token, result)

  return result
}

// ═══════════════════════════════════════════════════════════════════════════
// App
// ═══════════════════════════════════════════════════════════════════════════

const app = new Hono<{ Bindings: Env }>()

app.use('*', async (c, next) => {
  const allowedOrigins = c.env.ALLOWED_ORIGINS
    ? c.env.ALLOWED_ORIGINS.split(',').map((o) => o.trim())
    : []

  return cors({
    origin: (origin) => {
      if (allowedOrigins.length === 0) return ''
      return allowedOrigins.includes(origin) ? origin : ''
    },
    allowMethods: ['GET', 'POST', 'OPTIONS'],
    allowHeaders: ['Authorization', 'Content-Type', 'Cookie'],
    maxAge: 86400,
  })(c, next)
})

// Health check
app.get('/health', (c) => c.json({ status: 'ok', service: 'auth' }))

// Verify token (POST body or query param)
app.post('/verify', async (c) => {
  const raw: unknown = await c.req.json().catch(() => ({}))
  const body = (typeof raw === 'object' && raw !== null) ? raw as Record<string, unknown> : {}
  const bodyToken = typeof body.token === 'string' ? body.token : undefined
  const token = bodyToken || c.req.query('token')

  if (!token) {
    return c.json({ valid: false, error: 'Token required' }, 400)
  }

  const result = await verifyToken(token, c.env)
  return c.json(result)
})

// Verify from Authorization header
app.get('/verify', async (c) => {
  const auth = c.req.header('Authorization')
  let token: string | undefined

  if (auth?.startsWith('Bearer ')) {
    token = auth.slice(7)
  } else {
    token = c.req.query('token')
  }

  if (!token) {
    return c.json({ valid: false, error: 'Token required' }, 400)
  }

  const result = await verifyToken(token, c.env)
  return c.json(result)
})

// Get user from token
app.get('/me', async (c) => {
  const auth = c.req.header('Authorization')
  const cookie = c.req.cookie('auth')
  const token = auth?.startsWith('Bearer ') ? auth.slice(7) : cookie

  if (!token) {
    return c.json({ error: 'Not authenticated' }, 401)
  }

  const result = await verifyToken(token, c.env)
  if (!result.valid) {
    return c.json({ error: result.error || 'Invalid token' }, 401)
  }

  return c.json(result.user)
})

// Invalidate cache for a token
app.post('/invalidate', async (c) => {
  // Require authentication (Bearer token, API key, or admin token)
  const auth = c.req.header('Authorization')
  const callerToken = auth?.startsWith('Bearer ') ? auth.slice(7) : undefined

  if (!callerToken) {
    return c.json({ error: 'Authentication required' }, 401)
  }

  const authResult = await verifyToken(callerToken, c.env)
  if (!authResult.valid) {
    return c.json({ error: authResult.error || 'Invalid credentials' }, 401)
  }

  const raw: unknown = await c.req.json().catch(() => ({}))
  const body = (typeof raw === 'object' && raw !== null) ? raw as Record<string, unknown> : {}
  const token = typeof body.token === 'string' ? body.token : undefined

  if (!token) {
    return c.json({ error: 'Token required' }, 400)
  }

  try {
    const cache = caches.default
    const hash = await hashToken(token)
    const cacheKey = new Request(`${CACHE_URL_PREFIX}${hash}`)
    await cache.delete(cacheKey)
    return c.json({ invalidated: true })
  } catch {
    return c.json({ invalidated: false, error: 'Cache operation failed' })
  }
})

// ═══════════════════════════════════════════════════════════════════════════
// RPC Entrypoint - Zero bundle overhead for consumers
// ═══════════════════════════════════════════════════════════════════════════

import { WorkerEntrypoint } from 'cloudflare:workers'

/** Auth result for RPC calls */
export type AuthResult =
  | { ok: true; user: AuthUser }
  | { ok: false; status: number; error: string }

/**
 * AuthRPC - Workers RPC entrypoint for authentication
 *
 * Consumers bind to this via service bindings for zero-bundle-overhead auth.
 *
 * @example
 * ```typescript
 * // wrangler.jsonc
 * "services": [{ "binding": "AUTH", "service": "auth-do", "entrypoint": "AuthRPC" }]
 *
 * // In your worker
 * const result = await env.AUTH.verifyToken(token)
 * ```
 */
export class AuthRPC extends WorkerEntrypoint<Env> {
  /**
   * Verify any token type (JWT, API key, admin token)
   * Results are cached for 5 minutes
   */
  async verifyToken(token: string): Promise<VerifyResult> {
    try {
      // Check required environment
      if (!this.env.WORKOS_CLIENT_ID) {
        return { valid: false, error: 'WORKOS_CLIENT_ID not configured' }
      }
      return await verifyToken(token, this.env)
    } catch (err) {
      console.error('[AuthRPC.verifyToken] Unexpected error:', err)
      return { valid: false, error: err instanceof Error ? err.message : 'Verification failed' }
    }
  }

  /**
   * Get user from token, returns null if invalid
   */
  async getUser(token: string): Promise<AuthUser | null> {
    const result = await this.verifyToken(token)
    return result.valid && result.user ? result.user : null
  }

  /**
   * Authenticate from Authorization header and/or cookie value
   * Returns structured result for middleware use
   */
  async authenticate(
    authorization?: string | null,
    cookie?: string | null
  ): Promise<AuthResult> {
    // Extract token from Authorization header or cookie
    const token =
      authorization?.replace(/^Bearer\s+/i, '') ||
      cookie?.match(/(?:^|;\s*)auth=([^;]+)/)?.[1]

    if (!token) {
      return { ok: false, status: 401, error: 'No token provided' }
    }

    const result = await this.verifyToken(token)

    if (!result.valid || !result.user) {
      return { ok: false, status: 401, error: result.error || 'Invalid token' }
    }

    return { ok: true, user: result.user }
  }

  /**
   * Check if token has any of the specified roles
   */
  async hasRoles(token: string, roles: string[]): Promise<boolean> {
    const user = await this.getUser(token)
    if (!user?.roles) return false
    return roles.some((r) => user.roles!.includes(r))
  }

  /**
   * Check if token has all of the specified permissions
   */
  async hasPermissions(token: string, permissions: string[]): Promise<boolean> {
    const user = await this.getUser(token)
    if (!user?.permissions) return false
    return permissions.every((p) => user.permissions!.includes(p))
  }

  /**
   * Check if token belongs to an admin user
   */
  async isAdmin(token: string): Promise<boolean> {
    return this.hasRoles(token, ['admin'])
  }

  /**
   * Invalidate cached result for a token
   */
  async invalidate(token: string): Promise<boolean> {
    try {
      const cache = caches.default
      const hash = await hashToken(token)
      const cacheKey = new Request(`${CACHE_URL_PREFIX}${hash}`)
      await cache.delete(cacheKey)
      return true
    } catch {
      return false
    }
  }
}

// Export Hono app as default (keeps HTTP API working)
export default app
