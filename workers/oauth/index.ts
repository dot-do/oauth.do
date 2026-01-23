/**
 * OAuth Worker - Full OAuth flow with WorkOS SDK
 *
 * This worker handles the complete OAuth flow:
 * - Authorization URL generation
 * - OAuth callback handling
 * - Token exchange
 * - Session/cookie management
 * - API key management
 *
 * This is the "heavy" worker that uses the WorkOS SDK.
 * The auth worker is lightweight and only does verification.
 *
 * @module oauth-worker
 */

import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { setCookie, getCookie, deleteCookie } from 'hono/cookie'
import { WorkOS } from '@workos-inc/node'

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════

interface Env {
  WORKOS_CLIENT_ID: string
  WORKOS_API_KEY: string
  WORKOS_COOKIE_PASSWORD: string
  REDIRECT_URI: string
  ALLOWED_ORIGINS?: string
  // KV for state storage (CSRF protection)
  OAUTH_STATE?: KVNamespace
}

interface OAuthState {
  redirectTo: string
  createdAt: number
  provider?: string
}

// ═══════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════

const STATE_TTL = 10 * 60 // 10 minutes
const SESSION_TTL = 7 * 24 * 60 * 60 // 7 days
const COOKIE_NAME = 'auth'

// ═══════════════════════════════════════════════════════════════════════════
// Utilities
// ═══════════════════════════════════════════════════════════════════════════

function generateState(): string {
  const array = new Uint8Array(32)
  crypto.getRandomValues(array)
  return Array.from(array, (b) => b.toString(16).padStart(2, '0')).join('')
}

async function hashApiKey(key: string): Promise<string> {
  const data = new TextEncoder().encode(key)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

async function signJWT(
  payload: Record<string, unknown>,
  secret: string,
  expiresIn: number
): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' }
  const now = Math.floor(Date.now() / 1000)
  const fullPayload = {
    ...payload,
    iat: now,
    exp: now + expiresIn,
  }

  const base64url = (data: string | Uint8Array): string => {
    const str = typeof data === 'string' ? data : new TextDecoder().decode(data)
    return btoa(str).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
  }

  const headerB64 = base64url(JSON.stringify(header))
  const payloadB64 = base64url(JSON.stringify(fullPayload))
  const data = `${headerB64}.${payloadB64}`

  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )

  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data))
  const signatureB64 = base64url(new Uint8Array(signature))

  return `${data}.${signatureB64}`
}

// ═══════════════════════════════════════════════════════════════════════════
// App
// ═══════════════════════════════════════════════════════════════════════════

const app = new Hono<{ Bindings: Env }>()

// CORS
app.use('*', async (c, next) => {
  const origins = c.env.ALLOWED_ORIGINS?.split(',') || ['*']
  return cors({ origin: origins })(c, next)
})

// Health check
app.get('/health', (c) => c.json({ status: 'ok', service: 'oauth' }))

// ═══════════════════════════════════════════════════════════════════════════
// Authorization Flow
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Start OAuth flow - redirects to WorkOS
 *
 * Query params:
 * - redirect_to: URL to redirect to after auth (default: /)
 * - provider: OAuth provider (optional)
 */
app.get('/authorize', async (c) => {
  const workos = new WorkOS(c.env.WORKOS_API_KEY)
  const redirectTo = c.req.query('redirect_to') || '/'
  const provider = c.req.query('provider')
  const state = generateState()

  // Store state for CSRF protection
  const stateData: OAuthState = {
    redirectTo,
    createdAt: Date.now(),
    provider,
  }

  if (c.env.OAUTH_STATE) {
    await c.env.OAUTH_STATE.put(`state:${state}`, JSON.stringify(stateData), {
      expirationTtl: STATE_TTL,
    })
  }

  const authorizationUrl = workos.userManagement.getAuthorizationUrl({
    clientId: c.env.WORKOS_CLIENT_ID,
    redirectUri: c.env.REDIRECT_URI,
    state,
    provider: provider as any,
  })

  return c.redirect(authorizationUrl)
})

/**
 * OAuth callback - exchanges code for token
 */
app.get('/callback', async (c) => {
  const code = c.req.query('code')
  const state = c.req.query('state')
  const error = c.req.query('error')
  const errorDescription = c.req.query('error_description')

  if (error) {
    return c.json({ error, description: errorDescription }, 400)
  }

  if (!code) {
    return c.json({ error: 'Missing authorization code' }, 400)
  }

  // Validate state (CSRF protection)
  let stateData: OAuthState | null = null
  if (state && c.env.OAUTH_STATE) {
    const stored = await c.env.OAUTH_STATE.get(`state:${state}`)
    if (stored) {
      stateData = JSON.parse(stored) as OAuthState
      await c.env.OAUTH_STATE.delete(`state:${state}`)
    }
  }

  if (!stateData) {
    return c.json({ error: 'Invalid state parameter' }, 400)
  }

  // Exchange code for tokens
  const workos = new WorkOS(c.env.WORKOS_API_KEY)

  try {
    const { user, accessToken, refreshToken } = await workos.userManagement.authenticateWithCode({
      clientId: c.env.WORKOS_CLIENT_ID,
      code,
    })

    // Create session JWT
    const sessionToken = await signJWT(
      {
        sub: user.id,
        email: user.email,
        name: `${user.firstName || ''} ${user.lastName || ''}`.trim(),
        // Include access token for API calls
        access_token: accessToken,
      },
      c.env.WORKOS_COOKIE_PASSWORD,
      SESSION_TTL
    )

    // Set cookie
    setCookie(c, COOKIE_NAME, sessionToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
      maxAge: SESSION_TTL,
      path: '/',
    })

    // Redirect to original destination
    return c.redirect(stateData.redirectTo)
  } catch (err) {
    console.error('OAuth callback error:', err)
    return c.json({ error: 'Authentication failed' }, 500)
  }
})

// ═══════════════════════════════════════════════════════════════════════════
// Session Management
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Get current user
 */
app.get('/me', async (c) => {
  const token = getCookie(c, COOKIE_NAME)
  if (!token) {
    return c.json({ error: 'Not authenticated' }, 401)
  }

  // Decode JWT (signature verification happens in auth worker)
  try {
    const [, payloadB64] = token.split('.')
    const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')))

    // Check expiration
    if (payload.exp && payload.exp < Date.now() / 1000) {
      deleteCookie(c, COOKIE_NAME)
      return c.json({ error: 'Session expired' }, 401)
    }

    return c.json({
      id: payload.sub,
      email: payload.email,
      name: payload.name,
    })
  } catch {
    return c.json({ error: 'Invalid session' }, 401)
  }
})

/**
 * Logout - clear session
 */
app.post('/logout', (c) => {
  deleteCookie(c, COOKIE_NAME)
  return c.json({ success: true })
})

app.get('/logout', (c) => {
  deleteCookie(c, COOKIE_NAME)
  const redirectTo = c.req.query('redirect_to') || '/'
  return c.redirect(redirectTo)
})

// ═══════════════════════════════════════════════════════════════════════════
// API Key Management
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Verify API key (called by auth worker via RPC)
 */
app.post('/verify-api-key', async (c) => {
  const body = await c.req.json().catch(() => ({})) as { key?: string }
  const key = body.key

  if (!key || !key.startsWith('sk_')) {
    return c.json({ valid: false, error: 'Invalid API key format' })
  }

  const workos = new WorkOS(c.env.WORKOS_API_KEY)

  try {
    // Use the API key as a bearer token to get user info
    const response = await fetch('https://api.workos.com/user_management/users/me', {
      headers: { Authorization: `Bearer ${key}` },
    })

    if (!response.ok) {
      return c.json({ valid: false, error: 'Invalid API key' })
    }

    const user = (await response.json()) as {
      id: string
      email: string
      first_name?: string
      last_name?: string
      organization_memberships?: Array<{ organization: { id: string } }>
    }

    return c.json({
      valid: true,
      user: {
        id: user.id,
        email: user.email,
        name: [user.first_name, user.last_name].filter(Boolean).join(' ') || undefined,
        organizationId: user.organization_memberships?.[0]?.organization?.id,
      },
    })
  } catch {
    return c.json({ valid: false, error: 'API key verification failed' })
  }
})

/**
 * Create API key for current user
 */
app.post('/api-keys', async (c) => {
  const token = getCookie(c, COOKIE_NAME)
  if (!token) {
    return c.json({ error: 'Not authenticated' }, 401)
  }

  // Decode JWT to get user
  const [, payloadB64] = token.split('.')
  const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')))

  if (!payload.access_token) {
    return c.json({ error: 'No access token in session' }, 400)
  }

  const body = await c.req.json().catch(() => ({})) as { name?: string }
  const name = body.name || 'API Key'

  // Use WorkOS to create an API key
  // Note: This requires the User Management API key feature
  // For now, we'll generate a simple key and store it
  const keyId = crypto.randomUUID()
  const keySecret = `sk_${generateState()}`
  const keyHash = await hashApiKey(keySecret)

  // TODO: Store key in KV or D1
  // For now, just return the key (it won't be verifiable without storage)

  return c.json({
    id: keyId,
    name,
    key: keySecret, // Only shown once!
    created_at: new Date().toISOString(),
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// Token Exchange (for CLI/agents)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Exchange authorization code for tokens (for CLI usage)
 */
app.post('/token', async (c) => {
  const body = await c.req.json().catch(() => ({})) as {
    grant_type?: string
    code?: string
    redirect_uri?: string
  }

  if (body.grant_type !== 'authorization_code') {
    return c.json({ error: 'unsupported_grant_type' }, 400)
  }

  if (!body.code) {
    return c.json({ error: 'invalid_request', error_description: 'Missing code' }, 400)
  }

  const workos = new WorkOS(c.env.WORKOS_API_KEY)

  try {
    const { user, accessToken, refreshToken } = await workos.userManagement.authenticateWithCode({
      clientId: c.env.WORKOS_CLIENT_ID,
      code: body.code,
    })

    return c.json({
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: 'Bearer',
      expires_in: 3600,
      user: {
        id: user.id,
        email: user.email,
        name: `${user.firstName || ''} ${user.lastName || ''}`.trim(),
      },
    })
  } catch (err) {
    console.error('Token exchange error:', err)
    return c.json({ error: 'invalid_grant' }, 400)
  }
})

export default app
