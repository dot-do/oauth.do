/**
 * oauth.do - OAuth authentication SDK and CLI for .do Platform
 *
 * @packageDocumentation
 */

export { auth, login, logout, getToken, isAuthenticated, buildAuthUrl } from './auth.js'
export { configure, getConfig } from './config.js'
export { authorizeDevice, pollForTokens } from './device.js'
export { ensureLoggedIn, forceLogin, ensureLoggedOut } from './login.js'
export type { LoginOptions, LoginResult } from './login.js'
export {
	FileTokenStorage,
	MemoryTokenStorage,
	LocalStorageTokenStorage,
	SecureFileTokenStorage,
	KeychainTokenStorage,
	CompositeTokenStorage,
	createSecureStorage,
} from './storage.js'
export type {
	OAuthConfig,
	User,
	AuthResult,
	DeviceAuthorizationResponse,
	TokenResponse,
	TokenError,
	TokenStorage,
} from './types.js'
