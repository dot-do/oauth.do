import { env } from 'cloudflare:workers'
import { type AssertOptions, AuthError, type AuthUser } from './types.js'
import { extractApiKey, extractToken, verifyApiKey, verifyJwtWithFetcher } from './verify.js'

// JWKS path - fetched via service binding, not public internet
const JWKS_PATH = '/.well-known/jwks.json'

/**
 * Get the OAUTH service binding for JWKS fetch
 */
function getOAuthFetcher(): Fetcher | null {
  return (env as { OAUTH?: Fetcher }).OAUTH || null
}

// Request context for current user
let currentRequest: Request | null = null
let currentUser: AuthUser | null | undefined = undefined

/**
 * Get the expected issuer from the request origin
 * Each platform service (collections.do, mcp.do, etc.) acts as its own OAuth provider
 * Note: WorkOS tokens have their own issuer (https://auth.apis.do or https://api.workos.com)
 * and are handled specially in verifyJwtWithFetcher
 */
function getExpectedIssuer(request: Request): string {
  const url = new URL(request.url)
  return `${url.protocol}//${url.hostname}`
}

/**
 * Set the current request context
 * Called by middleware before auth functions
 */
export function setRequestContext(request: Request): void {
  currentRequest = request
  currentUser = undefined // Reset user for new request
}

/**
 * Get the current request
 */
function getRequest(): Request {
  if (!currentRequest) {
    throw new Error('No request context. Use withAuth() middleware or call setRequestContext()')
  }
  return currentRequest
}

/**
 * Get authenticated user from current request (or null if not authenticated)
 * Supports:
 * - oauth.do JWTs (issuer matches request origin)
 * - WorkOS JWTs (issuer: https://auth.apis.do or https://api.workos.com)
 * - WorkOS API keys (X-API-Key header)
 */
export async function getUser(): Promise<AuthUser | null> {
  if (currentUser !== undefined) {
    return currentUser
  }

  const request = getRequest()

  // Try JWT first (supports both oauth.do and WorkOS tokens)
  const token = extractToken(request)
  if (token) {
    // Pass expected issuer for oauth.do tokens, but verifyJwtWithFetcher
    // will also accept WorkOS issuers (https://auth.apis.do, https://api.workos.com)
    const expectedIssuer = getExpectedIssuer(request)
    // Use service binding if available (fast), fallback to public URL (slow)
    const oauthFetcher = getOAuthFetcher()
    currentUser = await verifyJwtWithFetcher(token, JWKS_PATH, expectedIssuer, oauthFetcher)
    if (currentUser) return currentUser
  }

  // Try API key (WorkOS API keys via X-API-Key header)
  const apiKey = extractApiKey(request)
  if (apiKey) {
    const workosApiKey = (env as { WORKOS_API_KEY?: string }).WORKOS_API_KEY
    if (workosApiKey) {
      currentUser = await verifyApiKey(apiKey, workosApiKey)
      if (currentUser) return currentUser
    }
  }

  currentUser = null
  return null
}

/**
 * Assert user is authenticated
 * Throws AuthError if not, returns user if authenticated
 */
export async function assertAuth(options?: AssertOptions): Promise<AuthUser> {
  const user = await getUser()

  if (!user) {
    throw new AuthError('Authentication required', 'unauthorized')
  }

  // Check specific user
  if (options?.user && user.id !== options.user) {
    throw new AuthError('Access denied', 'forbidden', 403)
  }

  // Check specific org
  if (options?.org && user.org !== options.org) {
    throw new AuthError('Access denied to this organization', 'forbidden', 403)
  }

  // Check role
  if (options?.role && !user.roles?.includes(options.role)) {
    throw new AuthError(`Role '${options.role}' required`, 'forbidden', 403)
  }

  // Check permission
  if (options?.permission && !user.permissions?.includes(options.permission)) {
    throw new AuthError(`Permission '${options.permission}' required`, 'forbidden', 403)
  }

  return user
}

/**
 * Assert user is an admin
 */
export async function assertAdmin(): Promise<AuthUser> {
  return assertAuth({ role: 'admin' })
}

/**
 * Check if current request is authenticated (doesn't throw)
 */
export async function isAuthenticated(): Promise<boolean> {
  return (await getUser()) !== null
}

/**
 * Get login URL for redirects
 */
export function getLoginUrl(returnTo?: string): string {
  const request = getRequest()
  const url = new URL(request.url)
  const loginUrl = new URL('/login', url.origin)
  if (returnTo) {
    loginUrl.searchParams.set('returnTo', returnTo)
  } else {
    loginUrl.searchParams.set('returnTo', url.pathname + url.search)
  }
  return loginUrl.toString()
}
