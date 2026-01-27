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
 * Create the Hono app for HTTP routing
 */
function createApp(env: Env): Hono<{ Bindings: Env }> {
  const app = new Hono<{ Bindings: Env }>()

  // CORS
  app.use('*', async (c, next) => {
    const origins = c.env.ALLOWED_ORIGINS?.split(',') || ['*']
    return cors({ origin: origins })(c, next)
  })

  // Health check
  app.get('/health', (c) => c.json({ status: 'ok', service: 'oauth' }))

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

  app.post('/login', async (c) => {
    const stub = getOAuthDO(c.env)
    return stub.fetch(c.req.raw)
  })

  app.get('/callback', async (c) => {
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

  // ═══════════════════════════════════════════════════════════════════════════
  // Simple Login (first-party domains)
  // ═══════════════════════════════════════════════════════════════════════════

  app.get('/login', async (c) => {
    const stub = getOAuthDO(c.env)
    return stub.fetch(c.req.raw)
  })

  // Logout
  app.post('/logout', (c) => {
    return c.json({ success: true })
  })

  app.get('/logout', (c) => {
    const redirectTo = c.req.query('redirect_to') || '/'
    return c.redirect(redirectTo)
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
}
