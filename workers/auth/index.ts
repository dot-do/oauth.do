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
  // RPC binding to OAuth worker for API key verification
  OAUTH?: Fetcher
}

interface AuthUser {
  id: string
  email?: string
  name?: string
  organizationId?: string
  roles?: string[]
  permissions?: string[]
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

const TOKEN_CACHE_TTL = 5 * 60 // 5 minutes
const CACHE_URL_PREFIX = 'https://auth.oauth.do/_cache/'

// JWKS cache (module-level)
let jwksCache: jose.JWTVerifyGetKey | null = null
let jwksCacheExpiry = 0
const JWKS_CACHE_TTL = 60 * 60 * 1000 // 1 hour

// ═══════════════════════════════════════════════════════════════════════════
// Utilities
// ═══════════════════════════════════════════════════════════════════════════

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
    const data = { result, expiresAt: Date.now() + TOKEN_CACHE_TTL * 1000 }
    const response = new Response(JSON.stringify(data), {
      headers: { 'Cache-Control': `max-age=${TOKEN_CACHE_TTL}` },
    })
    await cache.put(cacheKey, response)
  } catch {
    // Non-fatal
  }
}

async function getJwks(clientId: string): Promise<jose.JWTVerifyGetKey> {
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
  try {
    const jwks = await getJwks(env.WORKOS_CLIENT_ID)
    const { payload } = await jose.jwtVerify(token, jwks, {
      audience: env.WORKOS_CLIENT_ID,
    })

    const user: AuthUser = {
      id: payload.sub || '',
      email: payload.email as string | undefined,
      name: payload.name as string | undefined,
      organizationId: payload.org_id as string | undefined,
      roles: payload.roles as string[] | undefined,
      permissions: payload.permissions as string[] | undefined,
    }

    return { valid: true, user }
  } catch (err) {
    return { valid: false, error: err instanceof Error ? err.message : 'JWT verification failed' }
  }
}

async function verifyAdminToken(token: string, env: Env): Promise<VerifyResult> {
  if (!env.ADMIN_TOKEN) return { valid: false, error: 'Admin token not configured' }

  // Constant-time comparison
  const tokenBytes = new TextEncoder().encode(token)
  const adminBytes = new TextEncoder().encode(env.ADMIN_TOKEN)

  if (tokenBytes.length !== adminBytes.length) {
    return { valid: false, error: 'Invalid admin token' }
  }

  let result = 0
  for (let i = 0; i < tokenBytes.length; i++) {
    result |= tokenBytes[i] ^ adminBytes[i]
  }

  if (result === 0) {
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

  // Try different verification methods
  if (token === env.ADMIN_TOKEN) {
    result = await verifyAdminToken(token, env)
  } else if (token.startsWith('sk_')) {
    result = await verifyApiKey(token, env)
  } else {
    // Assume JWT
    result = await verifyJWT(token, env)
  }

  // Cache successful results
  if (result.valid) {
    await cacheResult(token, result)
  }

  return result
}

// ═══════════════════════════════════════════════════════════════════════════
// App
// ═══════════════════════════════════════════════════════════════════════════

const app = new Hono<{ Bindings: Env }>()

app.use('*', cors())

// Health check
app.get('/health', (c) => c.json({ status: 'ok', service: 'auth' }))

// Verify token (POST body or query param)
app.post('/verify', async (c) => {
  const body = await c.req.json().catch(() => ({})) as { token?: string }
  const token = body.token || c.req.query('token')

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
  const body = await c.req.json().catch(() => ({})) as { token?: string }
  const token = body.token

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

export default app
