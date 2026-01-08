/**
 * oauth.do - Simple, secure authentication for humans and AI agents
 *
 * This is the browser-safe entry point with universal functions.
 * For Node.js CLI utilities that open the browser, import from 'oauth.do/node'
 *
 * @packageDocumentation
 */

// Browser-safe auth utilities
export { auth, getUser, login, logout, getToken, isAuthenticated, buildAuthUrl } from './auth.js'
export type { AuthProvider } from './auth.js'
export { configure, getConfig } from './config.js'
export { authorizeDevice, pollForTokens } from './device.js'

// GitHub Device Flow
export {
	startGitHubDeviceFlow,
	pollGitHubDeviceFlow,
	getGitHubUser,
} from './github-device.js'
export type {
	GitHubDeviceFlowOptions,
	GitHubDeviceAuthResponse,
	GitHubTokenResponse,
	GitHubUser,
} from './github-device.js'

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
export type { LoginOptions, LoginResult, OAuthProvider } from './login.js'
