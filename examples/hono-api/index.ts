/**
 * Hono API Example with oauth.do Authentication
 *
 * Demonstrates using oauth.do middleware with Hono for:
 * - JWT token verification
 * - API key authentication
 * - Role-based access control
 * - Smart browser vs API client handling
 */

import { Hono } from 'hono'
import { auth, requireAuth, assertAuth, assertRole, apiKey } from 'oauth.do/hono'

// Your WorkOS Client ID - get from https://dashboard.workos.com
const WORKOS_CLIENT_ID = 'client_01JQYTRXK9ZPD8JPJTKDCRB656'
const JWKS_URI = `https://api.workos.com/sso/jwks/${WORKOS_CLIENT_ID}`

const app = new Hono()

// ============================================================================
// Basic auth middleware - populates c.var.user if authenticated
// Does NOT reject unauthenticated requests
// ============================================================================

app.use('*', auth({
  jwksUri: JWKS_URI,
  clientId: WORKOS_CLIENT_ID,
}))

// ============================================================================
// Public route - accessible to everyone
// ============================================================================

app.get('/', (c) => {
  const user = c.var.user
  return c.json({
    message: 'Welcome to the API',
    authenticated: c.var.isAuth,
    user: user ? { id: user.id, email: user.email } : null,
  })
})

// ============================================================================
// Protected route using requireAuth - returns 401 if not authenticated
// ============================================================================

app.get('/api/me', requireAuth({ jwksUri: JWKS_URI }), (c) => {
  return c.json({
    user: c.var.user,
    message: 'This is your protected user data',
  })
})

// ============================================================================
// Smart auth with assertAuth - redirects browsers, returns JSON for API clients
// ============================================================================

app.get('/dashboard', assertAuth({
  jwksUri: JWKS_URI,
  loginUrl: 'https://oauth.do/login',
}), (c) => {
  return c.json({
    message: 'Welcome to your dashboard',
    user: c.var.user,
  })
})

// ============================================================================
// Role-based access control
// ============================================================================

app.get('/admin', assertRole({
  jwksUri: JWKS_URI,
  roles: ['admin', 'superadmin'],
}), (c) => {
  return c.json({
    message: 'Admin area',
    user: c.var.user,
  })
})

// ============================================================================
// API key authentication for programmatic access
// ============================================================================

app.get('/api/data', apiKey({
  headerName: 'X-API-Key',
  verify: async (key, c) => {
    // Implement your API key verification logic here
    // Return user object if valid, null if invalid
    if (key === 'test-api-key') {
      return {
        id: 'api-user-123',
        email: 'api@example.com',
        name: 'API User',
      }
    }
    return null
  },
}), (c) => {
  return c.json({
    data: [1, 2, 3],
    user: c.var.user,
  })
})

// ============================================================================
// Skip auth for certain paths
// ============================================================================

app.get('/health', (c) => c.json({ status: 'ok' }))
app.get('/public', (c) => c.json({ message: 'Public endpoint' }))

// ============================================================================
// Export for Cloudflare Workers or run locally
// ============================================================================

export default app

// For local development with Node.js
// Uncomment below to run with `npx tsx index.ts`
/*
import { serve } from '@hono/node-server'
serve({ fetch: app.fetch, port: 3000 }, (info) => {
  console.log(`Server running at http://localhost:${info.port}`)
})
*/
