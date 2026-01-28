import type { MiddlewareHandler } from 'hono'
import { setRequestContext, getUser, assertAuth as _assertAuth, assertAdmin as _assertAdmin, getLoginUrl, type AuthUser, type AssertOptions, AuthError } from './index.js'

// Extend Hono context with user
declare module 'hono' {
  interface ContextVariableMap {
    user: AuthUser | null
  }
}

/**
 * Middleware that enriches request with user info (doesn't require auth)
 */
export function withAuth(): MiddlewareHandler {
  return async (c, next) => {
    setRequestContext(c.req.raw)
    const user = await getUser()
    c.set('user', user)
    return next()
  }
}

/**
 * Middleware that requires authentication
 * Redirects to /login for browsers, returns 401 for API requests
 */
export function requireAuth(options?: AssertOptions): MiddlewareHandler {
  return async (c, next) => {
    setRequestContext(c.req.raw)

    try {
      const user = await _assertAuth(options)
      c.set('user', user)
      return next()
    } catch (e) {
      if (e instanceof AuthError) {
        // Redirect browsers to login
        const accept = c.req.header('Accept') || ''
        if (accept.includes('text/html') && e.code === 'unauthorized') {
          return c.redirect(getLoginUrl())
        }
        return c.json({ error: e.code, message: e.message }, e.status as 401 | 403)
      }
      throw e
    }
  }
}

/**
 * Middleware that requires admin role
 */
export function requireAdmin(): MiddlewareHandler {
  return async (c, next) => {
    setRequestContext(c.req.raw)

    try {
      const user = await _assertAdmin()
      c.set('user', user)
      return next()
    } catch (e) {
      if (e instanceof AuthError) {
        return c.json({ error: e.code, message: e.message }, e.status as 401 | 403)
      }
      throw e
    }
  }
}

// Re-export for convenience
export { getUser, getLoginUrl, AuthError }
export type { AuthUser, AssertOptions }
