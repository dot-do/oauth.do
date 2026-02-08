/**
 * Deploy your own OAuth 2.1 Server
 *
 * A minimal Cloudflare Worker that runs a full OAuth 2.1 authorization server
 * using @dotdo/oauth. This server can issue tokens to downstream clients
 * (Claude, ChatGPT, custom apps) while delegating user authentication to an
 * upstream provider (WorkOS, Auth0, etc.) or using built-in dev mode.
 *
 * Endpoints provided out of the box:
 *
 *   Discovery
 *   - GET  /.well-known/oauth-authorization-server   (RFC 8414)
 *   - GET  /.well-known/oauth-protected-resource     (draft-ietf-oauth-resource-metadata)
 *   - GET  /.well-known/jwks.json                    (JWKS)
 *
 *   Authorization
 *   - GET  /authorize                                (authorization endpoint)
 *   - GET  /callback                                 (upstream OAuth callback)
 *
 *   Token
 *   - POST /token                                    (token endpoint)
 *   - POST /revoke                                   (RFC 7009)
 *   - POST /introspect                               (RFC 7662)
 *   - GET  /userinfo                                 (OpenID Connect)
 *
 *   Client Registration
 *   - POST /register                                 (RFC 7591)
 *
 *   Device Flow
 *   - POST /device_authorization                     (RFC 8628)
 *   - GET  /device                                   (verification page)
 *
 * Run locally:   wrangler dev
 * Deploy:        wrangler deploy
 */

import { Hono } from 'hono'
import { createOAuth21Server, MemoryOAuthStorage } from '@dotdo/oauth'
import type { OAuth21ServerConfig } from '@dotdo/oauth'

// ---------------------------------------------------------------------------
// Environment type (matches wrangler.jsonc vars + secrets)
// ---------------------------------------------------------------------------

interface Env {
  ISSUER: string
  DEV_MODE?: string

  // Upstream provider secrets — set via `wrangler secret put`
  WORKOS_API_KEY?: string
  WORKOS_CLIENT_ID?: string
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

const app = new Hono<{ Bindings: Env }>()

/**
 * In-memory storage works for local development and single-instance Workers.
 * For production, replace with DOSQLiteStorage (Durable Object backed) or
 * CollectionsOAuthStorage (@dotdo/collections backed).
 */
const storage = new MemoryOAuthStorage()

app.get('/health', (c) => c.json({ status: 'ok' }))

/**
 * Mount the OAuth 2.1 server at the root.
 *
 * We use app.all() so the server handles every HTTP method on every path
 * that it defines. The createOAuth21Server() call returns a Hono sub-app
 * with all the RFC-compliant routes pre-configured.
 */
app.all('/*', (c) => {
  const env = c.env
  const isDevMode = env.DEV_MODE === 'true'

  const config: OAuth21ServerConfig = {
    issuer: env.ISSUER || 'http://localhost:8787',
    storage,

    // Dynamic client registration — let any MCP client register itself
    enableDynamicRegistration: true,

    // Token lifetimes
    accessTokenTtl: 3600,      // 1 hour
    refreshTokenTtl: 2592000,  // 30 days
    authCodeTtl: 600,          // 10 minutes

    // Scopes your server supports
    scopes: ['openid', 'profile', 'email', 'offline_access'],

    // Enable debug logging in dev
    debug: isDevMode,

    // CORS — allow all origins in dev, restrict in production
    allowedOrigins: isDevMode ? ['*'] : undefined,

    // Callbacks
    onUserAuthenticated: (user) => {
      console.log(`[OAuth] User authenticated: ${user.email ?? user.id}`)
    },
    onTokenRevoked: (token) => {
      console.log(`[OAuth] Token revoked: ${token.slice(0, 8)}...`)
    },
  }

  // -----------------------------------------------------------------------
  // Dev mode — no upstream provider required
  // -----------------------------------------------------------------------
  if (isDevMode) {
    config.devMode = {
      enabled: true,
      users: [
        { id: 'user_1', email: 'alice@example.com', password: 'password', name: 'Alice' },
        { id: 'user_2', email: 'bob@example.com', password: 'password', name: 'Bob' },
      ],
      // Accept any email/password combination and create the user on the fly
      allowAnyCredentials: true,
    }
  }

  // -----------------------------------------------------------------------
  // Production — delegate authentication to an upstream provider
  // -----------------------------------------------------------------------
  if (!isDevMode && env.WORKOS_API_KEY && env.WORKOS_CLIENT_ID) {
    config.upstream = {
      provider: 'workos',
      apiKey: env.WORKOS_API_KEY,
      clientId: env.WORKOS_CLIENT_ID,
    }
  }

  const oauthServer = createOAuth21Server(config)
  return oauthServer.fetch(c.req.raw, c.env)
})

export default app
