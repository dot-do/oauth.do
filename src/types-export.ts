/**
 * Type-only exports for oauth.do
 *
 * Usage:
 * import type { User, AuthResult, TokenStorage } from 'oauth.do/types'
 *
 * For @dotdo/types equivalents (camelCase, stricter):
 * import type { DotdoUser, DotdoTokenResponse, DotdoTokenStorage } from 'oauth.do/types'
 *
 * For wire protocol types (snake_case, RFC compliant):
 * import type { TokenResponseWire, DeviceAuthorizationResponseWire } from 'oauth.do/types'
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
	// Re-exported @dotdo/types equivalents (camelCase SDK types)
	DotdoUser,
	DotdoDeviceAuthorizationResponse,
	DotdoTokenResponse,
	DotdoDeviceFlowError,
	DotdoStoredTokenData,
	DotdoTokenStorage,
	// Wire Protocol types from @dotdo/types (snake_case, RFC compliant)
	DeviceAuthorizationResponseWire,
	TokenResponseWire,
	OAuthErrorWire,
	AuthorizationRequestWire,
	OAuthUser,
	WireToSdk,
	SdkToWire,
} from './types'
