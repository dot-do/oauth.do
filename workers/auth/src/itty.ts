import { setRequestContext, getUser, assertAuth as _assertAuth, assertAdmin as _assertAdmin, getLoginUrl, type AuthUser, type AssertOptions, AuthError } from './index.js'

// Extend Request with user
declare global {
  interface Request {
    user?: AuthUser | null
  }
}

/**
 * Middleware that enriches request with user info (doesn't require auth)
 */
export async function withAuth(request: Request): Promise<void> {
  setRequestContext(request)
  request.user = await getUser()
}

/**
 * Middleware that requires authentication
 * Returns Response if not authenticated, undefined to continue
 */
export async function requireAuth(request: Request, options?: AssertOptions): Promise<Response | undefined> {
  setRequestContext(request)

  try {
    request.user = await _assertAuth(options)
    return undefined // Continue to next handler
  } catch (e) {
    if (e instanceof AuthError) {
      // Redirect browsers to login
      const accept = request.headers.get('Accept') || ''
      if (accept.includes('text/html') && e.code === 'unauthorized') {
        return Response.redirect(getLoginUrl(), 302)
      }
      return Response.json({ error: e.code, message: e.message }, { status: e.status })
    }
    throw e
  }
}

/**
 * Middleware that requires admin role
 */
export async function requireAdmin(request: Request): Promise<Response | undefined> {
  setRequestContext(request)

  try {
    request.user = await _assertAdmin()
    return undefined
  } catch (e) {
    if (e instanceof AuthError) {
      return Response.json({ error: e.code, message: e.message }, { status: e.status })
    }
    throw e
  }
}

// Re-export for convenience
export { getUser, getLoginUrl, AuthError }
export type { AuthUser, AssertOptions }
