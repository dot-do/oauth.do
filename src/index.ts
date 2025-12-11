/**
 * oauth.do - OAuth authentication SDK and CLI for .do Platform
 *
 * This is the browser-safe entry point.
 * For CLI utilities that open the browser, import from 'oauth.do/cli'
 *
 * @packageDocumentation
 */

// Browser-safe auth utilities
export { auth, getUser, login, logout, getToken, isAuthenticated, buildAuthUrl } from './auth.js'
export type { AuthProvider } from './auth.js'
export { configure, getConfig } from './config.js'
export { authorizeDevice, pollForTokens } from './device.js'

// Storage utilities (browser-safe - uses dynamic imports for Node.js features)
export {
	FileTokenStorage,
	MemoryTokenStorage,
	LocalStorageTokenStorage,
	SecureFileTokenStorage,
	KeychainTokenStorage,
	CompositeTokenStorage,
	createSecureStorage,
} from './storage.js'

// Types
export type {
	OAuthConfig,
	User,
	AuthResult,
	DeviceAuthorizationResponse,
	TokenResponse,
	TokenError,
	TokenStorage,
} from './types.js'

// Re-export login types only (not functions - they use 'open' package)
export type { LoginOptions, LoginResult } from './login.js'
