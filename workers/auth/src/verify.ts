import { verify, decode } from '@tsndr/cloudflare-worker-jwt'
import type { AuthUser } from './types.js'

// JWKS cache
interface JWK {
  kty: string
  kid: string
  use?: string
  alg?: string
  n?: string
  e?: string
}

interface JWKSCache {
  keys: JWK[]
  fetchedAt: number
}

// Multiple JWKS caches for different issuers
const jwksCaches = new Map<string, JWKSCache>()
const JWKS_CACHE_TTL = 60 * 60 * 1000 // 1 hour (keys rarely change)

// WorkOS configuration
const WORKOS_ISSUERS = ['https://auth.apis.do', 'https://api.workos.com']
const DEFAULT_WORKOS_CLIENT_ID = 'client_01JQYTRXK9ZPD8JPJTKDCRB656'

/** Resolve WorkOS client ID from env (if available) or use default */
function getWorkosClientId(): string {
  try {
    // Cloudflare Workers use `env` from cloudflare:workers
    const { env } = require('cloudflare:workers') as { env: { WORKOS_CLIENT_ID?: string } }
    return env?.WORKOS_CLIENT_ID || DEFAULT_WORKOS_CLIENT_ID
  } catch {
    return DEFAULT_WORKOS_CLIENT_ID
  }
}

function getWorkosJwksUrl(clientId?: string): string {
  return `https://api.workos.com/sso/jwks/${clientId || getWorkosClientId()}`
}

// oauth.do issuer (for browser auth flow)
const OAUTH_DO_ISSUER = 'https://oauth.do'
const OAUTH_DO_JWKS_URL = 'https://oauth.do/.well-known/jwks.json'

/**
 * Check if an issuer is a WorkOS issuer
 */
function isWorkOSIssuer(issuer: string): boolean {
  return WORKOS_ISSUERS.includes(issuer)
}

/**
 * Check if an issuer is the oauth.do issuer
 */
function isOAuthDoIssuer(issuer: string): boolean {
  return issuer === OAUTH_DO_ISSUER
}

/**
 * Fetch and cache JWKS
 * @param jwksUrl - Full URL or path to JWKS (e.g., /.well-known/jwks.json or https://api.workos.com/sso/jwks/...)
 * @param fetcher - Optional service binding fetcher (faster than public URL)
 */
async function getJWKS(jwksUrl: string, fetcher?: Fetcher | null): Promise<JWK[]> {
  const now = Date.now()
  const cacheKey = fetcher ? `binding:${jwksUrl}` : jwksUrl

  const cached = jwksCaches.get(cacheKey)
  if (cached && (now - cached.fetchedAt) < JWKS_CACHE_TTL) {
    return cached.keys
  }

  let response: Response
  if (jwksUrl.startsWith('http')) {
    // Full URL - fetch directly (e.g., WorkOS JWKS)
    response = await fetch(jwksUrl)
  } else if (fetcher) {
    // Use service binding - much faster, no cold start penalty
    response = await fetcher.fetch(new Request(`https://oauth.do${jwksUrl}`))
  } else {
    // Fallback to public URL
    response = await fetch(`https://oauth.do${jwksUrl}`)
  }

  if (!response.ok) {
    throw new Error(`Failed to fetch JWKS from ${jwksUrl}: ${response.status}`)
  }

  const { keys } = await response.json() as { keys: JWK[] }

  jwksCaches.set(cacheKey, { keys, fetchedAt: now })

  return keys
}

/**
 * Find key in JWKS by kid
 */
function findKey(keys: JWK[], kid: string): JWK | undefined {
  return keys.find(k => k.kid === kid)
}

/**
 * Verify JWT token using JWKS
 */
// Custom JWT payload with our claims (oauth.do tokens)
interface OAuthPayload {
  scope?: string
  email?: string
  name?: string
  picture?: string
  image?: string
  org?: string
  roles?: string[]
  permissions?: string[]
}

// WorkOS JWT payload
interface WorkOSPayload {
  sub: string
  email?: string
  first_name?: string
  last_name?: string
  org_id?: string
  role?: string
  roles?: string[]
  permissions?: string[]
  entitlements?: string[]
  sid?: string
  jti?: string
  iat?: number
  exp?: number
  iss?: string
}

export async function verifyJwt(
  token: string,
  jwksUrl: string,
  issuer?: string
): Promise<AuthUser | null> {
  return verifyJwtWithFetcher(token, jwksUrl, issuer, null)
}

export async function verifyJwtWithFetcher(
  token: string,
  jwksPath: string,
  expectedIssuer?: string,
  fetcher?: Fetcher | null
): Promise<AuthUser | null> {
  try {
    // Decode to get the kid from header and issuer from payload
    const decoded = decode(token)
    const { header, payload } = decoded as {
      header: { kid?: string }
      payload: { iss?: string } & (OAuthPayload | WorkOSPayload)
    }
    const kid = header.kid
    const tokenIssuer = payload.iss

    if (!kid) {
      console.error('[AUTH] JWT missing kid in header')
      return null
    }

    // Determine which JWKS to use based on issuer
    let jwksUrl: string
    let allowedIssuers: string[]
    let useFetcher = true

    if (tokenIssuer && isWorkOSIssuer(tokenIssuer)) {
      // WorkOS token - use WorkOS JWKS
      jwksUrl = getWorkosJwksUrl()
      allowedIssuers = WORKOS_ISSUERS
      useFetcher = false
    } else if (tokenIssuer && isOAuthDoIssuer(tokenIssuer)) {
      // oauth.do token (browser auth flow) - use oauth.do JWKS
      jwksUrl = OAUTH_DO_JWKS_URL
      allowedIssuers = [OAUTH_DO_ISSUER]
      useFetcher = false
    } else {
      // Platform token with dynamic issuer - use service binding or fallback
      jwksUrl = jwksPath
      allowedIssuers = expectedIssuer ? [expectedIssuer] : []
    }

    // Fetch JWKS and find the key
    const keys = await getJWKS(jwksUrl, useFetcher ? fetcher : null)
    const jwk = findKey(keys, kid)

    if (!jwk) {
      console.error(`Key not found in JWKS: ${kid}`)
      return null
    }

    // Verify the token
    const result = await verify<OAuthPayload & WorkOSPayload>(token, jwk as any, { algorithm: 'RS256', throwError: true })

    if (!result) {
      return null
    }

    const verifiedPayload = result.payload

    // Validate issuer
    if (allowedIssuers.length > 0 && !allowedIssuers.includes(verifiedPayload.iss || '')) {
      console.error(`Invalid issuer: expected one of ${allowedIssuers.join(', ')}, got ${verifiedPayload.iss}`)
      return null
    }

    // Map payload to AuthUser (handle WorkOS, oauth.do, and platform formats)
    if (tokenIssuer && isWorkOSIssuer(tokenIssuer)) {
      // WorkOS token mapping
      const workosPayload = verifiedPayload as WorkOSPayload
      const name = [workosPayload.first_name, workosPayload.last_name].filter(Boolean).join(' ') || undefined
      return {
        id: workosPayload.sub,
        email: workosPayload.email,
        name,
        organizationId: workosPayload.org_id,
        org: workosPayload.org_id, // Backwards compatibility alias
        roles: workosPayload.roles || (workosPayload.role ? [workosPayload.role] : undefined),
        permissions: workosPayload.permissions,
      }
    } else {
      // oauth.do or platform token mapping (same format)
      const oauthPayload = verifiedPayload as OAuthPayload
      const scope = typeof oauthPayload.scope === 'string' ? oauthPayload.scope.split(' ') : undefined
      return {
        id: verifiedPayload.sub || '',
        email: oauthPayload.email,
        name: oauthPayload.name,
        image: oauthPayload.picture || oauthPayload.image,
        organizationId: oauthPayload.org,
        org: oauthPayload.org, // Backwards compatibility alias
        roles: oauthPayload.roles,
        permissions: oauthPayload.permissions || scope,
      }
    }
  } catch (e) {
    console.error('[AUTH] JWT verification failed:', e instanceof Error ? e.message : e)
    return null
  }
}


// WorkOS API key cache (in-memory, TTL 5 minutes)
const apiKeyCache = new Map<string, { user: AuthUser; expires: number }>()
const API_KEY_CACHE_TTL = 5 * 60 * 1000

/**
 * Verify WorkOS API key
 */
export async function verifyApiKey(
  apiKey: string,
  workosApiKey: string
): Promise<AuthUser | null> {
  // Check cache first
  const cached = apiKeyCache.get(apiKey)
  if (cached && cached.expires > Date.now()) {
    return cached.user
  }

  try {
    // Verify with WorkOS API
    const response = await fetch('https://api.workos.com/user_management/api_keys/verify', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${workosApiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ api_key: apiKey }),
    })

    if (!response.ok) {
      return null
    }

    const data = await response.json() as {
      user_id: string
      email?: string
      organization_id?: string
      permissions?: string[]
    }

    const user: AuthUser = {
      id: data.user_id,
      email: data.email,
      organizationId: data.organization_id,
      org: data.organization_id, // Backwards compatibility alias
      permissions: data.permissions,
    }

    // Cache the result
    apiKeyCache.set(apiKey, {
      user,
      expires: Date.now() + API_KEY_CACHE_TTL,
    })

    return user
  } catch (e) {
    console.error('API key verification failed:', e)
    return null
  }
}

/**
 * Extract token from request (cookie or Authorization header)
 */
export function extractToken(request: Request): string | null {
  // Try Authorization header first
  const authHeader = request.headers.get('Authorization')
  if (authHeader?.startsWith('Bearer ')) {
    return authHeader.slice(7)
  }

  // Try cookie
  const cookies = request.headers.get('Cookie')
  if (cookies) {
    const match = cookies.match(/(?:^|;\s*)auth=([^;]+)/)
    if (match) {
      return match[1]!
    }
  }

  return null
}

/**
 * Extract API key from request (X-API-Key header)
 */
export function extractApiKey(request: Request): string | null {
  return request.headers.get('X-API-Key')
}
