/**
 * Shared auth utilities used by both Hono and Itty Router middleware.
 *
 * Pure functions for JWT/user caching, JWKS resolution, and payload mapping.
 * No framework dependencies — only jose and Web APIs.
 *
 * @internal
 */

import type { JWTPayload } from 'jose'
import * as jose from 'jose'
import type { AuthUser } from './types.js'

// Cloudflare Workers Cache API type
declare const caches: {
  default: Cache
}

export const TOKEN_CACHE_TTL = 5 * 60 // 5 minutes
export const CACHE_URL_PREFIX = 'https://oauth.do/_cache/token/'

/**
 * Hash a token for cache key (avoids storing raw tokens in cache)
 */
export async function hashToken(token: string): Promise<string> {
  const data = new TextEncoder().encode(token)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * Get cached user from Cache API
 */
export async function getCachedUser(token: string): Promise<AuthUser | null> {
  try {
    const cache = caches.default
    const hash = await hashToken(token)
    const cacheKey = new Request(`${CACHE_URL_PREFIX}${hash}`)
    const cached = await cache.match(cacheKey)

    if (!cached) return null

    const data = (await cached.json()) as { user: AuthUser; expiresAt: number }
    if (data.expiresAt < Date.now()) return null

    return data.user
  } catch {
    return null
  }
}

/**
 * Cache user in Cache API
 */
export async function cacheUser(token: string, user: AuthUser): Promise<void> {
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
 * Convert JWT payload to AuthUser
 */
export function payloadToUser(payload: JWTPayload): AuthUser {
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
let jwksCacheInstance: jose.JWTVerifyGetKey | null = null
let jwksCacheExpiry = 0

/**
 * Get JWKS verifier with caching
 */
export async function getJwks(jwksUri: string, cacheTtl: number): Promise<jose.JWTVerifyGetKey> {
  const now = Date.now()
  if (jwksCacheInstance && jwksCacheExpiry > now) {
    return jwksCacheInstance
  }

  jwksCacheInstance = jose.createRemoteJWKSet(new URL(jwksUri))
  jwksCacheExpiry = now + cacheTtl * 1000
  return jwksCacheInstance
}
