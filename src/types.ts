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

// Import Wire Protocol types from @dotdo/types (RFC compliant, snake_case)
import type {
	DeviceFlowError as DotdoDeviceFlowError,
	DeviceAuthorizationResponseWire,
	TokenResponseWire,
	OAuthErrorWire,
	AuthorizationRequestWire,
	OAuthUser,
	WireToSdk,
	SdkToWire,
} from '@dotdo/types/auth'

/**
 * Device flow error types - re-exported from @dotdo/types
 *
 * Note: oauth.do also includes 'unknown' for unhandled errors
 */
export type { DeviceFlowError as DotdoDeviceFlowError } from '@dotdo/types/auth'

// Re-export Wire Protocol types for consumers
export type {
	DeviceAuthorizationResponseWire,
	TokenResponseWire,
	OAuthErrorWire,
	AuthorizationRequestWire,
	OAuthUser,
	WireToSdk,
	SdkToWire,
} from '@dotdo/types/auth'

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
 */
export interface AuthUser {
	id: string
	email?: string
	name?: string
	organizationId?: string
	roles?: string[]
	permissions?: string[]
	metadata?: Record<string, unknown>
}

/**
 * Re-export @dotdo/types User for consumers who want the full type
 */
export type { User as DotdoUser } from '@dotdo/types/auth'

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
 * Re-exported from @dotdo/types/auth as DeviceAuthorizationResponseWire.
 * Uses snake_case property names as per OAuth 2.0 Device Authorization Grant (RFC 8628).
 *
 * @see DeviceAuthorizationResponseWire for the underlying type
 */
export interface DeviceAuthorizationResponse extends DeviceAuthorizationResponseWire {
	/** Optional verification URI with user code embedded (required in oauth.do) */
	verification_uri_complete: string
	/** Minimum polling interval in seconds (required in oauth.do) */
	interval: number
}

/**
 * Re-export @dotdo/types DeviceAuthorizationResponse (camelCase version)
 */
export type { DeviceAuthorizationResponse as DotdoDeviceAuthorizationResponse } from '@dotdo/types/auth'

/**
 * Token response (OAuth wire format - snake_case)
 *
 * Extends TokenResponseWire from @dotdo/types/auth with optional user field.
 * Uses snake_case property names as per OAuth 2.0 token endpoint responses (RFC 6749).
 *
 * @see TokenResponseWire for the underlying type
 */
export interface TokenResponse extends TokenResponseWire {
	/** User information returned from authentication (oauth.do extension) */
	user?: User
}

/**
 * Re-export @dotdo/types TokenResponse (camelCase version)
 */
export type { TokenResponse as DotdoTokenResponse } from '@dotdo/types/auth'

/**
 * Token polling error types
 *
 * @remarks
 * Extends @dotdo/types DeviceFlowError with 'unknown' for unhandled errors.
 */
export type TokenError =
	| DotdoDeviceFlowError
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
 * Re-export @dotdo/types StoredTokenData for consumers who want the full type
 */
export type { StoredTokenData as DotdoStoredTokenData } from '@dotdo/types/auth'

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

/**
 * Re-export @dotdo/types TokenStorage for consumers who want the key-value interface
 */
export type { TokenStorage as DotdoTokenStorage } from '@dotdo/types/auth'
