/**
 * Authenticated user from JWT or API key
 */
export interface AuthUser {
  id: string
  email?: string
  name?: string
  image?: string
  org?: string
  roles?: string[]
  permissions?: string[]
}

/**
 * Auth assertion options
 */
export interface AssertOptions {
  /** Require specific user ID */
  user?: string
  /** Require specific org/tenant */
  org?: string
  /** Require specific role */
  role?: string
  /** Require specific permission */
  permission?: string
  /** Custom redirect URL (default: /login) */
  loginUrl?: string
}

/**
 * Auth error thrown when assertion fails
 */
export class AuthError extends Error {
  constructor(
    message: string,
    public code: 'unauthorized' | 'forbidden' | 'invalid_token',
    public status: number = code === 'forbidden' ? 403 : 401
  ) {
    super(message)
    this.name = 'AuthError'
  }
}
