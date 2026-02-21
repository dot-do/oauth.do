/**
 * Runtime type guards for JSON data validation
 *
 * These guards replace unsafe `as Type` assertions on data from
 * JSON.parse(), response.json(), and other untrusted sources.
 *
 * @module guards
 */

import type { User, TokenResponse, DeviceAuthorizationResponse, TokenError, StoredTokenData } from './types.js'

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isString(value: unknown): value is string {
  return typeof value === 'string'
}

function isNumber(value: unknown): value is number {
  return typeof value === 'number' && !Number.isNaN(value)
}


// ═══════════════════════════════════════════════════════════════════════════
// Validation Error
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Error thrown when runtime JSON validation fails
 */
export class ValidationError extends Error {
  constructor(
    public readonly expectedType: string,
    public readonly details: string,
    public readonly data?: unknown
  ) {
    super(`Invalid ${expectedType}: ${details}`)
    this.name = 'ValidationError'
  }
}

/**
 * Assert that data passes a type guard, throwing ValidationError if not
 */
export function assertValid<T>(
  data: unknown,
  guard: (value: unknown) => value is T,
  typeName: string
): T {
  if (!guard(data)) {
    throw new ValidationError(typeName, 'failed runtime validation', data)
  }
  return data
}

// ═══════════════════════════════════════════════════════════════════════════
// Type Guards — src/types.ts
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Check if data is a valid User object
 *
 * Required: id (string)
 * Optional: email (string), name (string)
 */
export function isUser(data: unknown): data is User {
  if (!isObject(data)) return false
  if (!isString(data.id)) return false
  if (data.email !== undefined && !isString(data.email)) return false
  if (data.name !== undefined && !isString(data.name)) return false
  return true
}

/**
 * Check if data is a valid login response ({ user: User, token: string })
 */
export function isLoginResponse(data: unknown): data is { user: User; token: string } {
  if (!isObject(data)) return false
  if (!isUser(data.user)) return false
  if (!isString(data.token)) return false
  return true
}

/**
 * Check if data is a valid TokenResponse (OAuth 2.0 wire format)
 *
 * Required: access_token (string)
 * Optional: token_type (string), expires_in (number), refresh_token (string), scope (string), user (User)
 *
 * Note: token_type is technically required by RFC 6749 but WorkOS device flow
 * responses omit it, so we treat it as optional for compatibility.
 */
export function isTokenResponse(data: unknown): data is TokenResponse {
  if (!isObject(data)) return false
  if (!isString(data.access_token)) return false
  if (data.token_type !== undefined && !isString(data.token_type)) return false
  if (data.expires_in !== undefined && !isNumber(data.expires_in)) return false
  if (data.refresh_token !== undefined && !isString(data.refresh_token)) return false
  if (data.scope !== undefined && !isString(data.scope)) return false
  if (data.user !== undefined && !isUser(data.user)) return false
  return true
}

/**
 * Check if data is a valid DeviceAuthorizationResponse (RFC 8628)
 *
 * Required: device_code, user_code, verification_uri, verification_uri_complete, expires_in, interval
 */
export function isDeviceAuthorizationResponse(data: unknown): data is DeviceAuthorizationResponse {
  if (!isObject(data)) return false
  if (!isString(data.device_code)) return false
  if (!isString(data.user_code)) return false
  if (!isString(data.verification_uri)) return false
  if (!isString(data.verification_uri_complete)) return false
  if (!isNumber(data.expires_in)) return false
  if (!isNumber(data.interval)) return false
  return true
}

/**
 * Check if data is a valid error response from token polling ({ error?: string })
 */
export function isErrorResponse(data: unknown): data is { error?: string } {
  if (!isObject(data)) return false
  if (data.error !== undefined && !isString(data.error)) return false
  return true
}

const VALID_TOKEN_ERRORS = new Set<string>([
  'authorization_pending',
  'slow_down',
  'access_denied',
  'expired_token',
  'unknown',
])

/**
 * Check if a string is a valid TokenError value
 */
export function isTokenError(value: unknown): value is TokenError {
  return isString(value) && VALID_TOKEN_ERRORS.has(value)
}

/**
 * Coerce an error string to TokenError, defaulting to 'unknown' for unrecognized values
 */
export function toTokenError(value: unknown): TokenError {
  if (isTokenError(value)) return value
  return 'unknown'
}

/**
 * Check if data is a valid StoredTokenData
 *
 * Required: accessToken (string)
 * Optional: refreshToken (string), expiresAt (number)
 */
export function isStoredTokenData(data: unknown): data is StoredTokenData {
  if (!isObject(data)) return false
  if (!isString(data.accessToken)) return false
  if (data.refreshToken !== undefined && !isString(data.refreshToken)) return false
  if (data.expiresAt !== undefined && !isNumber(data.expiresAt)) return false
  return true
}

// ═══════════════════════════════════════════════════════════════════════════
// Type Guards — GitHub Device Flow
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Check if data is a valid GitHub device authorization wire response
 *
 * Required: device_code, user_code, verification_uri, expires_in, interval
 */
export function isGitHubDeviceAuthWireResponse(
  data: unknown
): data is { device_code: string; user_code: string; verification_uri: string; expires_in: number; interval: number } {
  if (!isObject(data)) return false
  if (!isString(data.device_code)) return false
  if (!isString(data.user_code)) return false
  if (!isString(data.verification_uri)) return false
  if (!isNumber(data.expires_in)) return false
  if (!isNumber(data.interval)) return false
  return true
}

/**
 * Check if data is a successful GitHub token wire response
 */
export function isGitHubTokenWireSuccess(
  data: unknown
): data is { access_token: string; token_type: string; scope: string } {
  if (!isObject(data)) return false
  if (!isString(data.access_token)) return false
  if (!isString(data.token_type)) return false
  if (!isString(data.scope)) return false
  return true
}

/**
 * Check if data is a GitHub token error wire response
 */
export function isGitHubTokenWireError(
  data: unknown
): data is { error: string; error_description?: string; error_uri?: string } {
  if (!isObject(data)) return false
  if (!isString(data.error)) return false
  if (data.error_description !== undefined && !isString(data.error_description)) return false
  if (data.error_uri !== undefined && !isString(data.error_uri)) return false
  return true
}

type GitHubTokenError = 'authorization_pending' | 'slow_down' | 'expired_token' | 'access_denied' | 'unknown'

const VALID_GITHUB_TOKEN_ERRORS = new Set<string>([
  'authorization_pending',
  'slow_down',
  'expired_token',
  'access_denied',
  'unknown',
])

/**
 * Coerce an error string to GitHubTokenError, defaulting to 'unknown'
 */
export function toGitHubTokenError(value: unknown): GitHubTokenError {
  if (isString(value) && VALID_GITHUB_TOKEN_ERRORS.has(value)) return value as GitHubTokenError
  return 'unknown'
}

/**
 * Check if data is a valid GitHub user wire response
 *
 * Required: id (number), login (string), avatar_url (string)
 * Optional: email (string|null), name (string|null)
 */
export function isGitHubUserWireResponse(
  data: unknown
): data is { id: number; login: string; email: string | null; name: string | null; avatar_url: string } {
  if (!isObject(data)) return false
  if (!isNumber(data.id)) return false
  if (!isString(data.login)) return false
  if (!isString(data.avatar_url)) return false
  // email and name can be string or null
  if (data.email !== null && data.email !== undefined && !isString(data.email)) return false
  if (data.name !== null && data.name !== undefined && !isString(data.name)) return false
  return true
}

// ═══════════════════════════════════════════════════════════════════════════
// Type Guards — Workers (auth worker)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Verify result from the auth worker
 */
export interface VerifyResult {
  valid: boolean
  user?: {
    id: string
    email?: string
    name?: string
    [key: string]: unknown
  }
  error?: string
  cached?: boolean
}

/**
 * Check if data is a valid VerifyResult
 */
export function isVerifyResult(data: unknown): data is VerifyResult {
  if (!isObject(data)) return false
  if (typeof data.valid !== 'boolean') return false
  if (data.error !== undefined && !isString(data.error)) return false
  if (data.cached !== undefined && typeof data.cached !== 'boolean') return false
  if (data.user !== undefined) {
    if (!isObject(data.user)) return false
    if (!isString((data.user as Record<string, unknown>).id)) return false
  }
  return true
}

/**
 * WorkOS user response shape
 */
export function isWorkOSUserResponse(
  data: unknown
): data is { id: string; email: string; first_name?: string; last_name?: string } {
  if (!isObject(data)) return false
  if (!isString(data.id)) return false
  if (!isString(data.email)) return false
  if (data.first_name !== undefined && !isString(data.first_name)) return false
  if (data.last_name !== undefined && !isString(data.last_name)) return false
  return true
}
