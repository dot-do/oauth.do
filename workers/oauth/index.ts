/**
 * OAuth Worker - Routes to OAuth Durable Object
 *
 * This worker routes OAuth requests to the OAuthDO Durable Object,
 * which provides persistent storage and JWT signing capabilities.
 * Extends WorkerEntrypoint for RPC support.
 *
 * @module oauth-worker
 */

import { WorkerEntrypoint } from 'cloudflare:workers'
import { Hono } from 'hono'
import { cors } from 'hono/cors'
import type { OAuthDO } from './oauth-do.js'

// Re-export the Durable Object class
export { OAuthDO } from './oauth-do.js'

/**
 * Environment bindings
 */
interface Env {
  // Durable Object binding
  OAUTH_DO: DurableObjectNamespace<OAuthDO>
  // Static assets binding
  ASSETS: Fetcher
  // WorkOS credentials
  WORKOS_CLIENT_ID: string
  WORKOS_API_KEY: string
  WORKOS_COOKIE_PASSWORD: string
  // Redirect URI
  REDIRECT_URI: string
  // CORS
  ALLOWED_ORIGINS?: string
  // KV for legacy state storage
  OAUTH_STATE?: KVNamespace
  // Stripe (optional)
  STRIPE_SECRET_KEY?: string
  STRIPE_WEBHOOK_SECRET?: string
  // Branding for @mdxui/auth app
  APP_NAME?: string
  APP_TAGLINE?: string
  // Rate limiting
  RATE_LIMITER: RateLimiter
  RATE_LIMITER_STRICT: RateLimiter
}

/**
 * Introspection response type
 */
interface IntrospectionResponse {
  active: boolean
  sub?: string
  client_id?: string
  scope?: string
  exp?: number
  iat?: number
  iss?: string
  aud?: string | string[]
  [key: string]: unknown
}

/**
 * Get the OAuth Durable Object stub
 * Uses a singleton pattern - all requests go to the same DO instance
 */
function getOAuthDO(env: Env): DurableObjectStub<OAuthDO> {
  const id = env.OAUTH_DO.idFromName('oauth-singleton')
  return env.OAUTH_DO.get(id)
}

/**
 * API key validation result
 */
interface ApiKeyValidationResult {
  valid: boolean
  id?: string
  name?: string
  organization_id?: string
  permissions?: string[]
  error?: string
}

/**
 * Validate a WorkOS API key (sk_...) against the WorkOS API
 *
 * Shared logic used by both the HTTP endpoint and RPC method.
 */
async function validateWorkosApiKey(apiKey: string, workosApiKey: string): Promise<ApiKeyValidationResult> {
  if (!apiKey || !apiKey.startsWith('sk_')) {
    return { valid: false, error: 'Invalid API key format' }
  }

  try {
    const response = await fetch('https://api.workos.com/api_keys/validations', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${workosApiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ value: apiKey }),
    })

    if (!response.ok) {
      return { valid: false, error: 'API key validation failed' }
    }

    const data = await response.json() as {
      id: string
      name: string
      organization_id?: string
      permissions?: string[]
      created_at: string
      last_used_at?: string
    }

    return {
      valid: true,
      id: data.id,
      name: data.name,
      organization_id: data.organization_id,
      permissions: data.permissions || [],
    }
  } catch (err) {
    console.error('API key validation error:', err)
    return { valid: false, error: 'Validation request failed' }
  }
}

/**
 * Create the Hono app for HTTP routing
 */
function createApp(env: Env): Hono<{ Bindings: Env }> {
  const app = new Hono<{ Bindings: Env }>()

  // CORS
  app.use('*', async (c, next) => {
    const origins = c.env.ALLOWED_ORIGINS?.split(',') || ['*']
    return cors({ origin: origins })(c, next)
  })

  // Rate limiting - strict for sensitive endpoints
  const strictPaths = new Set(['/token', '/register', '/exchange', '/login', '/validate-api-key'])
  app.use('*', async (c, next) => {
    const path = new URL(c.req.url).pathname
    // Skip rate limiting for static assets and well-known endpoints
    if (path.startsWith('/.well-known') || path === '/health') {
      return next()
    }
    const ip = c.req.header('cf-connecting-ip') || 'unknown'
    const limiter = strictPaths.has(path) ? c.env.RATE_LIMITER_STRICT : c.env.RATE_LIMITER
    const { success } = await limiter.limit({ key: `${ip}:${path}` })
    if (!success) {
      return c.json({ error: 'rate_limit_exceeded', error_description: 'Too many requests' }, 429)
    }
    return next()
  })

  // Health check
  app.get('/health', (c) => c.json({ status: 'ok', service: 'oauth' }))

  // Runtime config for @mdxui/auth SPA
  app.get('/auth-config.json', (c) => {
    return c.json({
      clientId: c.env.WORKOS_CLIENT_ID,
      redirectUri: c.env.REDIRECT_URI,
      appName: c.env.APP_NAME || 'oauth.do',
      tagline: c.env.APP_TAGLINE || 'Universal Authentication',
      onUnauthenticated: 'signIn',
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // OAuth 2.1 Endpoints - Route to Durable Object
  // ═══════════════════════════════════════════════════════════════════════════

  // Well-known endpoints
  app.get('/.well-known/oauth-authorization-server', async (c) => {
    const stub = getOAuthDO(c.env)
    return stub.fetch(c.req.raw)
  })

  app.get('/.well-known/oauth-protected-resource', async (c) => {
    const stub = getOAuthDO(c.env)
    return stub.fetch(c.req.raw)
  })

  app.get('/.well-known/jwks.json', async (c) => {
    const stub = getOAuthDO(c.env)
    return stub.fetch(c.req.raw)
  })

  // Authorization flow
  app.get('/authorize', async (c) => {
    const stub = getOAuthDO(c.env)
    return stub.fetch(c.req.raw)
  })

  // POST /login - for server-side OAuth flows (other domains)
  app.post('/login', async (c) => {
    const stub = getOAuthDO(c.env)
    return stub.fetch(c.req.raw)
  })

  // GET /login - redirect to WorkOS AuthKit for server-side flows (e.g., from collections.do)
  app.get('/login', async (c) => {
    const stub = getOAuthDO(c.env)
    return stub.fetch(c.req.raw)
  })

  // GET /callback - let SPA handle client-side WorkOS AuthKit flow
  // (Server-side flows use /api/callback instead)

  // /api/* routes for API-style callbacks
  app.get('/api/callback', async (c) => {
    const stub = getOAuthDO(c.env)
    return stub.fetch(c.req.raw)
  })

  app.get('/api/login', async (c) => {
    const stub = getOAuthDO(c.env)
    return stub.fetch(c.req.raw)
  })

  // Token endpoints
  app.post('/token', async (c) => {
    const stub = getOAuthDO(c.env)
    return stub.fetch(c.req.raw)
  })

  app.post('/introspect', async (c) => {
    const stub = getOAuthDO(c.env)
    return stub.fetch(c.req.raw)
  })

  app.post('/revoke', async (c) => {
    const stub = getOAuthDO(c.env)
    return stub.fetch(c.req.raw)
  })

  // Dynamic client registration
  app.post('/register', async (c) => {
    const stub = getOAuthDO(c.env)
    return stub.fetch(c.req.raw)
  })

  // Platform token exchange (one-time code → JWT)
  app.post('/exchange', async (c) => {
    const stub = getOAuthDO(c.env)
    return stub.fetch(c.req.raw)
  })

  // API Key validation endpoint - validates WorkOS API keys (sk_...)
  app.post('/validate-api-key', async (c) => {
    const body = await c.req.json<{ value: string }>()
    const result = await validateWorkosApiKey(body.value, c.env.WORKOS_API_KEY)
    const status = !result.valid ? (result.error === 'Invalid API key format' ? 400 : result.error === 'Validation request failed' ? 500 : 401) : 200
    return c.json(result, status)
  })

  // Logout
  app.post('/logout', async (c) => {
    // Extract token from body or Authorization header
    let token: string | undefined
    try {
      const body = await c.req.json<{ token?: string }>()
      token = body?.token
    } catch {
      // No JSON body, check Authorization header
    }
    if (!token) {
      const authHeader = c.req.header('Authorization')
      if (authHeader?.startsWith('Bearer ')) {
        token = authHeader.slice(7)
      }
    }

    // If a token was provided, forward revocation to the Durable Object
    if (token) {
      try {
        const stub = getOAuthDO(c.env)
        const revokeRequest = new Request(new URL('/revoke', c.req.url).toString(), {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ token }),
        })
        await stub.fetch(revokeRequest)
      } catch (err) {
        console.error('Token revocation error during logout:', err)
        // Still return success - client-side logout should proceed
      }
    }

    return c.json({ success: true })
  })

  app.get('/logout', (c) => {
    const redirectTo = c.req.query('redirect_to') || '/'

    // Validate redirect_to against allowed origins to prevent open redirect
    if (redirectTo !== '/' && !redirectTo.startsWith('//')) {
      try {
        const url = new URL(redirectTo, 'https://placeholder.invalid')
        // If it's an absolute URL, check origin against allowed list
        if (/^https?:\/\//.test(redirectTo)) {
          const allowedOrigins = c.env.ALLOWED_ORIGINS?.split(',').map((o) => o.trim()) || []
          if (!allowedOrigins.includes(url.origin)) {
            return c.redirect('/')
          }
        } else if (!redirectTo.startsWith('/')) {
          // Reject anything that isn't a relative path starting with /
          return c.redirect('/')
        }
      } catch {
        // Invalid URL, redirect to /
        return c.redirect('/')
      }
    }

    return c.redirect(redirectTo)
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Static Assets / SPA Fallback
  // ═══════════════════════════════════════════════════════════════════════════

  // Serve static assets with SPA fallback (handled by not_found_handling = "single-page-application")
  app.all('*', async (c) => {
    return c.env.ASSETS.fetch(c.req.raw)
  })

  return app
}

/**
 * OAuth Worker with RPC support
 *
 * Extends WorkerEntrypoint to expose RPC methods that can be called
 * directly from other workers via service bindings.
 */
export default class OAuthWorker extends WorkerEntrypoint<Env> {
  private app: Hono<{ Bindings: Env }>

  constructor(ctx: ExecutionContext, env: Env) {
    super(ctx, env)
    this.app = createApp(env)
  }

  /**
   * HTTP fetch handler - delegates to Hono app
   */
  override async fetch(request: Request): Promise<Response> {
    return this.app.fetch(request, this.env)
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // RPC Methods - Callable by other workers via service binding
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Introspect a token via Workers RPC
   *
   * This allows other workers to validate tokens without making HTTP requests.
   *
   * @param token - The access token to introspect
   * @returns Introspection response with active status and claims
   */
  async introspect(token: string): Promise<IntrospectionResponse> {
    const stub = getOAuthDO(this.env)

    // Create a proper RFC 7662 introspection request
    const body = new URLSearchParams()
    body.set('token', token)

    const request = new Request('https://oauth.do/introspect', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body,
    })

    const response = await stub.fetch(request)

    if (!response.ok) {
      return { active: false }
    }

    return response.json() as Promise<IntrospectionResponse>
  }

  /**
   * Validate a WorkOS API key via Workers RPC
   *
   * This allows other workers to validate API keys without making HTTP requests.
   *
   * @param apiKey - The API key to validate (sk_...)
   * @returns Validation response with key details or error
   */
  async validateApiKey(apiKey: string): Promise<ApiKeyValidationResult> {
    return validateWorkosApiKey(apiKey, this.env.WORKOS_API_KEY)
  }
}
