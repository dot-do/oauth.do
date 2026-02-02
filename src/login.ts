/**
 * CLI-centric login utilities
 * Handles device flow with browser auto-launch for CLI apps
 */

import { authorizeDevice, pollForTokens } from './device.js'
import type { OAuthProvider } from './device.js'
import { createSecureStorage } from './storage.js'
import { refreshAccessToken, getUser } from './auth.js'
import type { StoredTokenData } from './types.js'
import { getConfig } from './config.js'
import { getEnv } from './utils.js'

// Debug logging - enable with DEBUG=oauth.do or DEBUG=oauth.do:login
function debug(...args: unknown[]): void {
	const debugEnv = getEnv('DEBUG') || ''
	if (debugEnv.includes('oauth.do') || debugEnv === '*') {
		console.log('[oauth.do:login]', ...args)
	}
}

export type { OAuthProvider } from './device.js'

export interface LoginOptions {
	/** Open browser automatically (default: true) */
	openBrowser?: boolean
	/** Custom print function for output */
	print?: (message: string) => void
	/** OAuth provider to use directly (bypasses AuthKit login screen) */
	provider?: OAuthProvider
	/** Storage to use (default: createSecureStorage()) */
	storage?: {
		getToken: () => Promise<string | null>
		setToken: (token: string) => Promise<void>
		removeToken: () => Promise<void>
		getTokenData?: () => Promise<StoredTokenData | null>
		setTokenData?: (data: StoredTokenData) => Promise<void>
	}
}

export interface LoginResult {
	token: string
	isNewLogin: boolean
}

// Buffer time before expiration to trigger refresh (5 minutes)
const REFRESH_BUFFER_MS = 5 * 60 * 1000

// Singleton promise for login/refresh operations
// Prevents multiple concurrent login attempts (race condition)
let loginInProgress: Promise<LoginResult> | null = null
let refreshInProgress: Promise<LoginResult> | null = null

// Cache of the last successful token result to avoid re-reading storage
// and to serve parallel callers without triggering multiple refreshes
let cachedResult: { token: string; expiresAt?: number } | null = null

/**
 * Reset internal state (for testing only)
 */
export function _resetLoginState(): void {
	loginInProgress = null
	refreshInProgress = null
	cachedResult = null
}

/**
 * Check if token is expired or about to expire
 */
function isTokenExpired(expiresAt?: number): boolean {
	if (!expiresAt) return false // Can't determine, assume valid
	return Date.now() >= expiresAt - REFRESH_BUFFER_MS
}

/**
 * Internal refresh logic with singleton protection
 */
async function doRefresh(
	tokenData: StoredTokenData,
	storage: LoginOptions['storage']
): Promise<LoginResult> {
	debug('doRefresh called')

	// Check if a refresh is already in progress
	if (refreshInProgress) {
		debug('Refresh already in progress, waiting...')
		return refreshInProgress
	}

	refreshInProgress = (async () => {
		try {
			debug('Calling refreshAccessToken with refresh token:', tokenData.refreshToken?.substring(0, 20) + '...')
			const newTokens = await refreshAccessToken(tokenData.refreshToken!)
			debug('refreshAccessToken returned:', {
				hasAccessToken: !!newTokens.access_token,
				hasRefreshToken: !!newTokens.refresh_token,
				expiresIn: newTokens.expires_in,
			})

			// Calculate new expiration time
			const expiresAt = newTokens.expires_in ? Date.now() + newTokens.expires_in * 1000 : undefined
			debug('New expiresAt:', expiresAt ? new Date(expiresAt).toISOString() : 'NOT SET (no expires_in)')

			// Store new token data
			const newData: StoredTokenData = {
				accessToken: newTokens.access_token,
				refreshToken: newTokens.refresh_token || tokenData.refreshToken,
				expiresAt,
			}

			if (storage?.setTokenData) {
				debug('Storing new token data via setTokenData')
				await storage.setTokenData(newData)
			} else if (storage?.setToken) {
				debug('WARNING: Storage does not have setTokenData, using setToken (refresh token will be LOST)')
				await storage.setToken(newTokens.access_token)
			} else {
				debug('ERROR: Storage has neither setTokenData nor setToken!')
			}

			// Update in-memory cache so parallel callers get the new token
			cachedResult = { token: newTokens.access_token, expiresAt }
			debug('Refresh complete, token cached')

			return { token: newTokens.access_token, isNewLogin: false }
		} finally {
			refreshInProgress = null
		}
	})()

	return refreshInProgress
}

/**
 * Internal device flow login with singleton protection
 */
async function doDeviceLogin(options: LoginOptions): Promise<LoginResult> {
	// Check if a login is already in progress
	if (loginInProgress) {
		return loginInProgress
	}

	const config = getConfig()
	const {
		openBrowser = true,
		print = console.log,
		provider,
		storage = createSecureStorage(config.storagePath),
	} = options

	loginInProgress = (async () => {
		try {
			print('\nLogging in...\n')

			const authResponse = await authorizeDevice({ provider })

			print(`To complete login:`)
			print(`  1. Visit: ${authResponse.verification_uri}`)
			print(`  2. Enter code: ${authResponse.user_code}`)
			print(`\n  Or open: ${authResponse.verification_uri_complete}\n`)

			// Auto-launch browser
			if (openBrowser) {
				try {
					const open = await import('open')
					await open.default(authResponse.verification_uri_complete)
					print('Browser opened automatically\n')
				} catch {
					// Silently fail if can't open browser
				}
			}

			print('Waiting for authorization...\n')

			const tokenResponse = await pollForTokens(
				authResponse.device_code,
				authResponse.interval,
				authResponse.expires_in
			)

			debug('Device flow token response:', {
				hasAccessToken: !!tokenResponse.access_token,
				hasRefreshToken: !!tokenResponse.refresh_token,
				expiresIn: tokenResponse.expires_in,
			})

			// Calculate expiration time
			const expiresAt = tokenResponse.expires_in ? Date.now() + tokenResponse.expires_in * 1000 : undefined
			debug('Calculated expiresAt:', expiresAt ? new Date(expiresAt).toISOString() : 'NOT SET')

			// Store full token data including refresh token
			const newData: StoredTokenData = {
				accessToken: tokenResponse.access_token,
				refreshToken: tokenResponse.refresh_token,
				expiresAt,
			}

			if (storage.setTokenData) {
				debug('Storing token data via setTokenData')
				await storage.setTokenData(newData)
			} else {
				debug('WARNING: setTokenData not available, refresh token LOST')
				await storage.setToken(tokenResponse.access_token)
			}

			print('Login successful!\n')

			return { token: tokenResponse.access_token, isNewLogin: true }
		} finally {
			loginInProgress = null
		}
	})()

	return loginInProgress
}

/**
 * Get existing token or perform device flow login
 * Handles browser launch and token storage automatically
 * Automatically refreshes expired tokens if refresh_token is available
 *
 * Uses singleton pattern to prevent multiple concurrent login/refresh attempts
 */
export async function ensureLoggedIn(options: LoginOptions = {}): Promise<LoginResult> {
	debug('ensureLoggedIn called')

	// Fast path: return cached token if still valid (no disk I/O, no race)
	if (cachedResult && cachedResult.expiresAt && !isTokenExpired(cachedResult.expiresAt)) {
		debug('Fast path: returning cached token (expires:', new Date(cachedResult.expiresAt).toISOString(), ')')
		return { token: cachedResult.token, isNewLogin: false }
	}

	// If a refresh or login is already in flight, wait for it
	if (refreshInProgress) {
		debug('Waiting for refresh already in progress')
		return refreshInProgress
	}
	if (loginInProgress) {
		debug('Waiting for login already in progress')
		return loginInProgress
	}

	const config = getConfig()
	const { storage = createSecureStorage(config.storagePath) } = options
	debug('Storage path:', config.storagePath)

	// Check for existing token data
	const hasGetTokenData = !!storage.getTokenData
	debug('Storage has getTokenData method:', hasGetTokenData)

	const tokenData = storage.getTokenData ? await storage.getTokenData() : null
	debug('TokenData from storage:', tokenData ? {
		hasAccessToken: !!tokenData.accessToken,
		hasRefreshToken: !!tokenData.refreshToken,
		expiresAt: tokenData.expiresAt ? new Date(tokenData.expiresAt).toISOString() : 'NOT SET',
		isExpired: tokenData.expiresAt ? isTokenExpired(tokenData.expiresAt) : 'unknown (no expiresAt)',
	} : 'NULL - no token data')

	const existingToken = tokenData?.accessToken || (await storage.getToken())
	debug('Existing token:', existingToken ? `${existingToken.substring(0, 20)}...` : 'NULL')

	if (existingToken) {
		// If we have expiration info and token is not expired, cache and return
		if (tokenData?.expiresAt && !isTokenExpired(tokenData.expiresAt)) {
			debug('Token has expiresAt and is NOT expired - returning existing token')
			cachedResult = { token: existingToken, expiresAt: tokenData.expiresAt }
			return { token: existingToken, isNewLogin: false }
		}

		// Token is expired or expiration unknown - try to refresh if we have a refresh token
		if (tokenData?.refreshToken) {
			debug('Has refresh token:', tokenData.refreshToken.substring(0, 20) + '...')

			// If token is definitely expired (has expiresAt and it's past), try refresh
			if (tokenData.expiresAt && isTokenExpired(tokenData.expiresAt)) {
				debug('Token IS EXPIRED - attempting refresh')
				try {
					const result = await doRefresh(tokenData, storage)
					debug('Refresh SUCCEEDED')
					return result
				} catch (error) {
					// Refresh failed - fall through to validate or re-login
					debug('Refresh FAILED:', error)
					console.warn('Token refresh failed:', error)
				}
			} else if (!tokenData.expiresAt) {
				// No expiration info - validate token first, only refresh if invalid
				debug('No expiresAt - validating token with getUser()')
				const { user } = await getUser(existingToken)
				if (user) {
					debug('Token is VALID (user found) - returning existing token')
					cachedResult = { token: existingToken }
					return { token: existingToken, isNewLogin: false }
				}
				debug('Token is INVALID (no user) - attempting refresh')
				// Token invalid, try to refresh
				try {
					const result = await doRefresh(tokenData, storage)
					debug('Refresh SUCCEEDED')
					return result
				} catch (error) {
					// Refresh failed - fall through to device flow
					debug('Refresh FAILED:', error)
					console.warn('Token refresh failed:', error)
				}
			}
		} else {
			debug('NO refresh token available')
			// No refresh token - validate with network call
			debug('Validating token with getUser()')
			const { user } = await getUser(existingToken)
			if (user) {
				debug('Token is VALID (user found) - returning existing token')
				cachedResult = { token: existingToken }
				return { token: existingToken, isNewLogin: false }
			}
			debug('Token is INVALID (no user)')
		}
	} else {
		debug('No existing token found')
	}

	// No valid token, start device flow (with singleton protection)
	debug('>>> TRIGGERING DEVICE FLOW (browser login) <<<')
	return doDeviceLogin(options)
}

/**
 * Force a new login (ignores existing token)
 */
export async function forceLogin(options: LoginOptions = {}): Promise<LoginResult> {
	const config = getConfig()
	const { storage = createSecureStorage(config.storagePath) } = options
	await storage.removeToken()
	return ensureLoggedIn(options)
}

/**
 * Logout and remove stored token
 */
export async function ensureLoggedOut(options: LoginOptions = {}): Promise<void> {
	const config = getConfig()
	const { print = console.log, storage = createSecureStorage(config.storagePath) } = options
	await storage.removeToken()
	print('Logged out successfully\n')
}
