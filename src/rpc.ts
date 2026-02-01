/**
 * oauth.do/rpc - Type definitions for Workers RPC authentication
 *
 * This module exports ONLY types - zero runtime code, zero bundle size.
 * Use with service bindings for zero-overhead authentication.
 *
 * @example
 * ```typescript
 * import type { AuthRPC, AuthUser } from 'oauth.do/rpc'
 *
 * // In your env.d.ts
 * declare module 'cloudflare:workers' {
 *   interface Env {
 *     AUTH: Service<AuthRPC>
 *   }
 * }
 *
 * // Usage
 * const result = await env.AUTH.verifyToken(token)
 * ```
 *
 * @packageDocumentation
 */

// ═══════════════════════════════════════════════════════════════════════════
// Cloudflare Workers Types
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Cloudflare Workers Service binding type
 * This represents an RPC-capable service binding
 */
export type Service<T> = T

// ═══════════════════════════════════════════════════════════════════════════
// Core Types
// ═══════════════════════════════════════════════════════════════════════════
export { type AuthUser } from "./types.js";
import type { AuthUser } from "./types.js";
}

/**
 * Result of token verification (discriminated union on `valid`)
 */
export type VerifyResult =
  | { valid: true; user: AuthUser; cached?: boolean }
  | { valid: false; error: string }

/**
 * Structured auth result for middleware use
 */
export type AuthResult =
  | { ok: true; user: AuthUser }
  | { ok: false; status: number; error: string }

// ═══════════════════════════════════════════════════════════════════════════
// RPC Interface
// ═══════════════════════════════════════════════════════════════════════════

/**
 * AuthRPC interface - the contract for the auth service binding
 *
 * All methods are async and designed for Workers RPC calls.
 */
export interface AuthRPC {
  /**
   * Verify any token type (JWT, API key, admin token)
   * Results are cached for 5 minutes
   *
   * @param token - The token to verify
   * @returns Verification result with user info if valid
   */
  verifyToken(token: string): Promise<VerifyResult>

  /**
   * Get user from token
   *
   * @param token - The token to decode
   * @returns User info or null if invalid
   */
  getUser(token: string): Promise<AuthUser | null>

  /**
   * Authenticate from Authorization header and/or cookie
   * Designed for middleware use - returns structured result
   *
   * @param authorization - Authorization header value (e.g., "Bearer xxx")
   * @param cookie - Cookie header value
   * @returns Auth result with user or error
   */
  authenticate(
    authorization?: string | null,
    cookie?: string | null
  ): Promise<AuthResult>

  /**
   * Check if token has any of the specified roles
   *
   * @param token - The token to check
   * @param roles - Roles to check for (any match = true)
   */
  hasRoles(token: string, roles: string[]): Promise<boolean>

  /**
   * Check if token has all of the specified permissions
   *
   * @param token - The token to check
   * @param permissions - Permissions required (all must match)
   */
  hasPermissions(token: string, permissions: string[]): Promise<boolean>

  /**
   * Check if token belongs to an admin user
   *
   * @param token - The token to check
   */
  isAdmin(token: string): Promise<boolean>

  /**
   * Invalidate cached result for a token
   * Use when user permissions change
   *
   * @param token - The token to invalidate
   * @returns Whether invalidation succeeded
   */
  invalidate(token: string): Promise<boolean>
}

// ═══════════════════════════════════════════════════════════════════════════
// Type Helpers
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Service binding type for AuthRPC
 * Use this in your Env interface
 *
 * @example
 * ```typescript
 * interface Env {
 *   AUTH: AuthBinding
 * }
 * ```
 */
export type AuthBinding = Service<AuthRPC>

/**
 * Auth context attached to requests by middleware
 */
export interface AuthContext {
  /** Authenticated user */
  user: AuthUser
  /** Always true when context exists */
  isAuth: true
  /** The token used for authentication */
  token?: string
}
