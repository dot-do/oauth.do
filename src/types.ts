/**
 * @module types
 *
 * Type definitions for oauth.do authentication library.
 *
 * ## Migration notes for @dotdo/types
 *
 * This module uses Wire Protocol types from @dotdo/types/auth for OAuth compliance:
 * - `DeviceAuthorizationResponse` = `DeviceAuthorizationResponseWire` (RFC 8628)
 * - `TokenResponse` = `TokenResponseWire` + user field (RFC 6749)
 *
 * ### Types with shape differences (defined locally):
 * - `OAuthConfig` - oauth.do uses client-side config (apiUrl, clientId, storagePath)
 *   vs @dotdo/types uses full provider config (redirectUri, scopes, provider, pkce)
 *
 * - `User` - oauth.do uses simple `{ id, email?, name? }` with index signature
 *   vs @dotdo/types uses rich `{ $id, $type, email (required), firstName, lastName, ... }`
 *
 * - `StoredTokenData` - oauth.do makes expiresAt optional
 *   vs @dotdo/types requires expiresAt and issuedAt
 *
 * - `TokenStorage` - oauth.do uses different method signatures for backwards compatibility
 */

// Note: @dotdo/types is an optional peer dependency
// These types are defined locally for build compatibility when @dotdo/types is not installed

/**
 * Device flow error types
 */
export type DeviceFlowError = 'authorization_pending' | 'slow_down' | 'access_denied' | 'expired_token'

/**
 * OAuth configuration options
 *
 * @remarks
 * This differs from @dotdo/types OAuthConfig which is designed for full OAuth provider
 * configuration. oauth.do's OAuthConfig is focused on client-side SDK configuration.
 */
export interface OAuthConfig {
	/**
	 * Base URL for API endpoints
	 * @default 'https://apis.do'
	 */
	apiUrl?: string

	/**
	 * Client ID for OAuth flow
	 */
	clientId?: string

	/**
	 * AuthKit domain for device authorization
	 * @default 'login.oauth.do'
	 */
	authKitDomain?: string

	/**
	 * Custom fetch implementation
	 */
	fetch?: typeof fetch

	/**
	 * Custom path for token storage
	 * Supports ~ for home directory (e.g., '~/.studio/tokens.json')
	 * @default '~/.oauth.do/token'
	 */
	storagePath?: string
}

/**
 * User information returned from auth endpoints
 *
 * @remarks
 * This differs from @dotdo/types User which requires $id, $type, and email.
 * oauth.do's User is more permissive for flexibility with different auth providers.
 *
 * @see DotdoUser for the full @dotdo/types User type
 */
export interface User {
	id: string
	email?: string
	name?: string
	[key: string]: unknown
}

/**
 * Authenticated user information for middleware contexts
 *
 * This is the canonical AuthUser type for the oauth.do ecosystem.
 * All consuming code should use this type or a compatible subset.
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
 * Authentication result
 */
export interface AuthResult {
	user: User | null
	token?: string
}

/**
 * Device authorization response (OAuth wire format - snake_case)
 *
 * Uses snake_case property names as per OAuth 2.0 Device Authorization Grant (RFC 8628).
 */
export interface DeviceAuthorizationResponse {
	/** The device verification code */
	device_code: string
	/** The end-user verification code */
	user_code: string
	/** The end-user verification URI */
	verification_uri: string
	/** Optional verification URI with user code embedded */
	verification_uri_complete: string
	/** Lifetime in seconds of the device_code and user_code */
	expires_in: number
	/** Minimum polling interval in seconds */
	interval: number
}

/**
 * Token response (OAuth wire format - snake_case)
 *
 * Uses snake_case property names as per OAuth 2.0 token endpoint responses (RFC 6749).
 */
export interface TokenResponse {
	/** The access token issued by the authorization server */
	access_token: string
	/** The type of the token issued (always "Bearer") */
	token_type: string
	/** The lifetime in seconds of the access token */
	expires_in?: number
	/** The refresh token, which can be used to obtain new access tokens */
	refresh_token?: string
	/** The scope of the access token */
	scope?: string
	/** User information returned from authentication (oauth.do extension) */
	user?: User
}

/**
 * Token polling error types
 *
 * @remarks
 * Extends DeviceFlowError with 'unknown' for unhandled errors.
 */
export type TokenError =
	| DeviceFlowError
	| 'unknown'

/**
 * Stored token data including refresh token and expiration
 *
 * @remarks
 * This is a minimal subset of @dotdo/types StoredTokenData.
 * oauth.do makes expiresAt optional for backwards compatibility with simple token storage.
 *
 * @see DotdoStoredTokenData for the full type with tokenType, scope, idToken, issuedAt, and raw
 */
export interface StoredTokenData {
	/** The OAuth access token */
	accessToken: string
	/** The refresh token for obtaining new access tokens */
	refreshToken?: string
	/** Token expiration timestamp (ms since epoch) */
	expiresAt?: number
}

/**
 * Token storage interface
 *
 * @remarks
 * oauth.do uses a different interface than @dotdo/types TokenStorage:
 * - oauth.do: Simple getToken/setToken/removeToken methods (backwards compatible)
 * - @dotdo/types: Key-value style get(key)/set(key, token)/delete(key)/clear()
 *
 * The oauth.do interface is simpler for CLI/single-user scenarios,
 * while @dotdo/types TokenStorage is designed for multi-user/keyed storage.
 *
 * @see DotdoTokenStorage for the key-value based interface
 */
export interface TokenStorage {
	/** Get the stored access token */
	getToken(): Promise<string | null>
	/** Store an access token */
	setToken(token: string): Promise<void>
	/** Remove the stored token */
	removeToken(): Promise<void>
	/** Get full token data (optional for backwards compatibility) */
	getTokenData?(): Promise<StoredTokenData | null>
	/** Store full token data (optional for backwards compatibility) */
	setTokenData?(data: StoredTokenData): Promise<void>
}
