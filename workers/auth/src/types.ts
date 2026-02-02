/**
 * Authenticated user from JWT or API key
 *
 * This is compatible with the canonical AuthUser in oauth.do/src/types.ts.
 * Note: This worker uses `org` as the primary field, while the canonical type
 * uses `organizationId`. Both are supported for backwards compatibility.
 */
export interface AuthUser {
  /** Unique user identifier */
  id: string
  /** User's email address */
  email?: string
  /** User's display name */
  name?: string
  /** User's profile image URL */
  image?: string
  /** Organization/tenant ID (canonical name) */
  organizationId?: string
  /**
   * Organization/tenant ID (alias for backwards compatibility)
   * @deprecated Use organizationId instead
   */
  org?: string
  /** User roles for RBAC */
  roles?: string[]
  /** User permissions for fine-grained access */
  permissions?: string[]
  /** Additional user metadata */
  metadata?: Record<string, unknown>
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
