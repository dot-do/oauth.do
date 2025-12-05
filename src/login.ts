/**
 * CLI-centric login utilities
 * Handles device flow with browser auto-launch for CLI apps
 */

import { authorizeDevice, pollForTokens } from './device.js'
import { createSecureStorage } from './storage.js'

export interface LoginOptions {
	/** Open browser automatically (default: true) */
	openBrowser?: boolean
	/** Custom print function for output */
	print?: (message: string) => void
	/** Storage to use (default: createSecureStorage()) */
	storage?: {
		getToken: () => Promise<string | null>
		setToken: (token: string) => Promise<void>
		removeToken: () => Promise<void>
	}
}

export interface LoginResult {
	token: string
	isNewLogin: boolean
}

/**
 * Get existing token or perform device flow login
 * Handles browser launch and token storage automatically
 */
export async function ensureLoggedIn(options: LoginOptions = {}): Promise<LoginResult> {
	const { openBrowser = true, print = console.log, storage = createSecureStorage() } = options

	// Check for existing token
	const existingToken = await storage.getToken()
	if (existingToken) {
		return { token: existingToken, isNewLogin: false }
	}

	// No token, start device flow
	print('\nLogging in...\n')

	const authResponse = await authorizeDevice()

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

	await storage.setToken(tokenResponse.access_token)
	print('Login successful!\n')

	return { token: tokenResponse.access_token, isNewLogin: true }
}

/**
 * Force a new login (ignores existing token)
 */
export async function forceLogin(options: LoginOptions = {}): Promise<LoginResult> {
	const { storage = createSecureStorage() } = options
	await storage.removeToken()
	return ensureLoggedIn(options)
}

/**
 * Logout and remove stored token
 */
export async function ensureLoggedOut(options: LoginOptions = {}): Promise<void> {
	const { print = console.log, storage = createSecureStorage() } = options
	await storage.removeToken()
	print('Logged out successfully\n')
}
