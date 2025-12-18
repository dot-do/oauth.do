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

/**
 * Check if token is expired or about to expire
 */
function isTokenExpired(expiresAt?: number): boolean {
	if (!expiresAt) return false // Can't determine, assume valid
	return Date.now() >= expiresAt - REFRESH_BUFFER_MS
}

/**
 * Get existing token or perform device flow login
 * Handles browser launch and token storage automatically
 * Automatically refreshes expired tokens if refresh_token is available
 */
export async function ensureLoggedIn(options: LoginOptions = {}): Promise<LoginResult> {
	const config = getConfig()
	const { openBrowser = true, print = console.log, provider, storage = createSecureStorage(config.storagePath) } = options

	// Check for existing token data
	const tokenData = storage.getTokenData ? await storage.getTokenData() : null
	const existingToken = tokenData?.accessToken || (await storage.getToken())

	if (existingToken) {
		// Check if token is expired
		if (tokenData && isTokenExpired(tokenData.expiresAt)) {
			// Try to refresh
			if (tokenData.refreshToken) {
				try {
					const newTokens = await refreshAccessToken(tokenData.refreshToken)

					// Calculate new expiration time
					const expiresAt = newTokens.expires_in
						? Date.now() + newTokens.expires_in * 1000
						: undefined

					// Store new token data
					const newData: StoredTokenData = {
						accessToken: newTokens.access_token,
						refreshToken: newTokens.refresh_token || tokenData.refreshToken,
						expiresAt,
					}

					if (storage.setTokenData) {
						await storage.setTokenData(newData)
					} else {
						await storage.setToken(newTokens.access_token)
					}

					return { token: newTokens.access_token, isNewLogin: false }
				} catch (error) {
					// Refresh failed - might need to re-login
					console.warn('Token refresh failed:', error)
					// Fall through to device flow
				}
			}
		} else {
			// Token exists and not expired - validate it
			const { user } = await getUser(existingToken)
			if (user) {
				return { token: existingToken, isNewLogin: false }
			}
			// Token invalid - try refresh if available
			if (tokenData?.refreshToken) {
				try {
					const newTokens = await refreshAccessToken(tokenData.refreshToken)
					const expiresAt = newTokens.expires_in
						? Date.now() + newTokens.expires_in * 1000
						: undefined

					const newData: StoredTokenData = {
						accessToken: newTokens.access_token,
						refreshToken: newTokens.refresh_token || tokenData.refreshToken,
						expiresAt,
					}

					if (storage.setTokenData) {
						await storage.setTokenData(newData)
					} else {
						await storage.setToken(newTokens.access_token)
					}

					return { token: newTokens.access_token, isNewLogin: false }
				} catch {
					// Refresh failed - need to re-login
				}
			}
		}
	}

	// No valid token, start device flow
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

	// Calculate expiration time
	const expiresAt = tokenResponse.expires_in
		? Date.now() + tokenResponse.expires_in * 1000
		: undefined

	// Store full token data including refresh token
	const newData: StoredTokenData = {
		accessToken: tokenResponse.access_token,
		refreshToken: tokenResponse.refresh_token,
		expiresAt,
	}

	if (storage.setTokenData) {
		await storage.setTokenData(newData)
	} else {
		await storage.setToken(tokenResponse.access_token)
	}

	print('Login successful!\n')

	return { token: tokenResponse.access_token, isNewLogin: true }
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
