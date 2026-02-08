/**
 * auth.do - Lightweight auth verification for the platform
 *
 * @example Using with Hono
 * ```typescript
 * import { withAuth, requireAuth, requireAdmin } from 'auth.do/hono'
 *
 * app.use('/*', withAuth())  // Enrich all requests with user
 * app.get('/admin/*', requireAuth(), requireAdmin())  // Require admin
 * app.get('/me', requireAuth(), (c) => c.json(c.var.user))
 * ```
 *
 * @example Using with itty-router
 * ```typescript
 * import { withAuth, requireAuth } from 'auth.do/itty'
 *
 * router.get('/api/*', withAuth, handler)
 * router.get('/admin/*', requireAuth, handler)
 * ```
 *
 * @example Direct usage
 * ```typescript
 * import { setRequestContext, getUser, assertAuth } from 'auth.do'
 *
 * setRequestContext(request)
 * const user = await getUser()  // null if not authenticated
 * const user = await assertAuth()  // throws if not authenticated
 * const admin = await assertAuth({ role: 'admin' })  // throws if not admin
 * ```
 */

// Core auth functions
export {
  setRequestContext,
  getUser,
  assertAuth,
  assertAdmin,
  isAuthenticated,
  getLoginUrl,
} from './auth.js'

// Verification utilities
export {
  verifyJwt,
  verifyApiKey,
  extractToken,
  extractApiKey,
} from './verify.js'

// Types
export {
  AuthError,
  type AuthUser,
  type AssertOptions,
} from './types.js'

// Worker entry point (for service binding RPC)
import { Hono } from 'hono'
import { setRequestContext, getUser, assertAuth } from './auth.js'
import { AuthError, type AuthUser } from './types.js'

const app = new Hono()

// Health check
app.get('/health', (c) => c.json({ status: 'ok', service: 'auth' }))

// RPC endpoint for assertAuth
app.post('/assert', async (c) => {
  let body: unknown
  try {
    body = await c.req.json()
  } catch {
    return c.json({ error: 'invalid_request', message: 'Invalid JSON body' }, 400)
  }

  if (typeof body !== 'object' || body === null) {
    return c.json({ error: 'invalid_request', message: 'Request body must be an object' }, 400)
  }

  const { request: reqData, options } = body as {
    request?: { url?: string; headers?: Record<string, string> }
    options?: { user?: string; org?: string; role?: string; permission?: string }
  }

  if (!reqData || typeof reqData.url !== 'string' || typeof reqData.headers !== 'object' || reqData.headers === null) {
    return c.json({ error: 'invalid_request', message: 'request.url (string) and request.headers (object) are required' }, 400)
  }

  // Reconstruct request from serialized data
  const headers = new Headers(reqData.headers)
  const request = new Request(reqData.url, { headers })
  setRequestContext(request)

  try {
    const user = await assertAuth(options)
    return c.json({ user })
  } catch (e) {
    if (e instanceof AuthError) {
      return c.json({ error: e.code, message: e.message }, e.status as 401 | 403)
    }
    throw e
  }
})

// RPC endpoint for getUser (withAuth)
app.post('/user', async (c) => {
  let body: unknown
  try {
    body = await c.req.json()
  } catch {
    return c.json({ error: 'invalid_request', message: 'Invalid JSON body' }, 400)
  }

  if (typeof body !== 'object' || body === null) {
    return c.json({ error: 'invalid_request', message: 'Request body must be an object' }, 400)
  }

  const { request: reqData } = body as {
    request?: { url?: string; headers?: Record<string, string> }
  }

  if (!reqData || typeof reqData.url !== 'string' || typeof reqData.headers !== 'object' || reqData.headers === null) {
    return c.json({ error: 'invalid_request', message: 'request.url (string) and request.headers (object) are required' }, 400)
  }

  const headers = new Headers(reqData.headers)
  const request = new Request(reqData.url, { headers })
  setRequestContext(request)

  const user = await getUser()
  return c.json({ user })
})

export default app

// Export types for service binding
export interface AuthService {
  assertAuth(request: Request, options?: { user?: string; org?: string; role?: string; permission?: string }): Promise<AuthUser>
  getUser(request: Request): Promise<AuthUser | null>
}
