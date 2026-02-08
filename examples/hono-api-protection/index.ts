/**
 * Protect a Hono API with oauth.do
 *
 * This example demonstrates every authentication pattern provided by oauth.do:
 *
 * 1. Optional auth — populate user context without blocking unauthenticated requests
 * 2. Required auth — reject unauthenticated requests with 401
 * 3. Smart auth (assertAuth) — redirect browsers to login, return JSON for API clients
 * 4. Role-based access control — restrict routes to users with specific roles
 * 5. Permission-based access control — require fine-grained permissions
 * 6. API key authentication — authenticate programmatic clients via X-API-Key header
 * 7. Combined auth — try JWT first, fall back to API key
 * 8. Session-based auth — encrypted cookie sessions with OAuth login flow
 *
 * Deploy to Cloudflare Workers with `wrangler deploy` or run locally with `npx tsx index.ts`.
 */

import { Hono } from 'hono'
import {
  auth,
  requireAuth,
  assertAuth,
  assertRole,
  assertPermission,
  apiKey,
  combined,
  sessionAuth,
  requireSession,
  createOAuthRoutes,
} from 'oauth.do/hono'
import type { AuthUser } from 'oauth.do/hono'

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// In production, read these from environment variables or wrangler.jsonc [vars].
// The JWKS URI points to your identity provider's JSON Web Key Set endpoint.
const JWKS_URI = 'https://api.workos.com/sso/jwks/client_01JQYTRXK9ZPD8JPJTKDCRB656'

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

const app = new Hono()

// ---------------------------------------------------------------------------
// 1. Optional auth — populates c.var.user if a valid JWT is present
//    Does NOT return 401 for unauthenticated requests.
// ---------------------------------------------------------------------------

app.use(
  '*',
  auth({
    jwksUri: JWKS_URI,
    // Skip auth entirely for health/readiness probes
    skip: (c) => c.req.path === '/health',
  }),
)

// ---------------------------------------------------------------------------
// Public routes
// ---------------------------------------------------------------------------

app.get('/', (c) => {
  return c.json({
    name: 'oauth.do Hono API Protection Example',
    authenticated: c.var.isAuth,
    user: c.var.user ? { id: c.var.user.id, email: c.var.user.email } : null,
    endpoints: {
      public: ['GET /', 'GET /health'],
      protected: ['GET /api/me', 'GET /api/projects'],
      admin: ['GET /admin/users'],
      apiKey: ['GET /api/data'],
    },
  })
})

app.get('/health', (c) => c.json({ status: 'ok' }))

// ---------------------------------------------------------------------------
// 2. Required auth — returns 401 JSON if no valid token
// ---------------------------------------------------------------------------

app.get(
  '/api/me',
  requireAuth({ jwksUri: JWKS_URI }),
  (c) => {
    // At this point c.var.user is guaranteed to be non-null
    const user = c.var.user!
    return c.json({
      id: user.id,
      email: user.email,
      name: user.name,
      organizationId: user.organizationId,
      roles: user.roles,
      permissions: user.permissions,
    })
  },
)

// ---------------------------------------------------------------------------
// 3. Smart auth (assertAuth) — browsers get redirected, API clients get JSON
// ---------------------------------------------------------------------------

app.get(
  '/dashboard',
  assertAuth({
    jwksUri: JWKS_URI,
    loginUrl: 'https://oauth.do/login',
    // Also accept API keys alongside JWTs
    apiKey: {
      verify: async (key) => lookupApiKey(key),
    },
    skip: (c) => c.req.path === '/dashboard/public',
  }),
  (c) => {
    return c.json({
      message: `Welcome back, ${c.var.user?.name ?? c.var.user?.email ?? 'user'}`,
      user: c.var.user,
    })
  },
)

// ---------------------------------------------------------------------------
// 4. Role-based access control
// ---------------------------------------------------------------------------

app.get(
  '/admin/users',
  assertRole({
    jwksUri: JWKS_URI,
    roles: ['admin', 'superadmin'],
  }),
  (c) => {
    return c.json({
      message: 'Admin area — listing all users',
      currentUser: c.var.user,
    })
  },
)

// ---------------------------------------------------------------------------
// 5. Permission-based access control
// ---------------------------------------------------------------------------

app.get(
  '/api/projects',
  assertPermission({
    jwksUri: JWKS_URI,
    permissions: ['projects:read'],
  }),
  (c) => {
    return c.json({
      projects: [
        { id: 'proj_1', name: 'Website Redesign' },
        { id: 'proj_2', name: 'Mobile App v2' },
      ],
      user: c.var.user,
    })
  },
)

// ---------------------------------------------------------------------------
// 6. API key authentication
// ---------------------------------------------------------------------------

app.get(
  '/api/data',
  apiKey({
    headerName: 'X-API-Key',
    verify: async (key) => lookupApiKey(key),
  }),
  (c) => {
    return c.json({
      data: { metrics: { mrr: 12500, customers: 42 } },
      authenticatedVia: 'api-key',
      user: c.var.user,
    })
  },
)

// ---------------------------------------------------------------------------
// 7. Combined auth — JWT first, then API key fallback
// ---------------------------------------------------------------------------

app.get(
  '/api/events',
  combined({
    auth: { jwksUri: JWKS_URI },
    apiKey: {
      verify: async (key) => lookupApiKey(key),
    },
  }),
  (c) => {
    return c.json({
      events: [
        { type: 'page_view', ts: Date.now() },
        { type: 'signup', ts: Date.now() - 60000 },
      ],
      user: c.var.user,
    })
  },
)

// ---------------------------------------------------------------------------
// 8. Session-based auth with OAuth login flow
// ---------------------------------------------------------------------------

// Mount OAuth routes (login, callback, logout, me, refresh)
app.route(
  '/auth',
  createOAuthRoutes({
    // In production, pass these via env:
    // workosApiKey: env.WORKOS_API_KEY,
    // clientId: env.WORKOS_CLIENT_ID,
    // session: { secret: env.SESSION_SECRET },
  }),
)

// Session-protected route
app.get(
  '/account',
  requireSession(),
  (c) => {
    const session = c.var.session!
    return c.json({
      userId: session.userId,
      email: session.email,
      name: session.name,
      organizationId: session.organizationId,
    })
  },
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Stub API key lookup. Replace with a real database or KV lookup in production.
 */
async function lookupApiKey(key: string): Promise<AuthUser | null> {
  // Example: accept a known test key
  const keys: Record<string, AuthUser> = {
    'sk_test_abc123': {
      id: 'user_api_1',
      email: 'api@example.com',
      name: 'API Service Account',
      roles: ['service'],
      permissions: ['projects:read', 'events:read'],
    },
  }
  return keys[key] ?? null
}

// ---------------------------------------------------------------------------
// Export for Cloudflare Workers
// ---------------------------------------------------------------------------

export default app
