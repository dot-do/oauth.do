/**
 * Type-only exports for oauth.do
 *
 * Usage:
 * import type { User, AuthResult, TokenStorage } from 'oauth.do/types'
 */
export type {
	// oauth.do native types
	OAuthConfig,
	User,
	AuthResult,
	DeviceAuthorizationResponse,
	TokenResponse,
	TokenError,
	StoredTokenData,
	TokenStorage,
	DeviceFlowError,
	AuthUser,
} from './types'
