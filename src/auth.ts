import { getConfig } from './config.js'
import type { User, AuthResult, TokenResponse, StoredTokenData } from './types.js'

/**
 * Resolve a secret that could be a plain string or a secrets store binding
 * Secrets store bindings have a .get() method that returns a Promise<string>
 * @see https://developers.cloudflare.com/workers/configuration/secrets/#secrets-store
 */
async function resolveSecret(value: unknown): Promise<string | null> {
	if (!value) return null
	if (typeof value === 'string') return value
	if (typeof value === 'object' && typeof (value as any).get === 'function') {
		return await (value as any).get()
	}
	return null
}

/**
 * Safe environment variable access (works in Node, browser, and Workers)
 */
function getEnv(key: string): string | undefined {
	// Check globalThis first (Workers)
	if ((globalThis as any)[key]) return (globalThis as any)[key]
	// Check process.env (Node.js)
	if (typeof process !== 'undefined' && process.env?.[key]) return process.env[key]
	return undefined
}

/**
 * Get current authenticated user
 * Calls GET /me endpoint
 *
 * @param token - Optional authentication token (will use DO_TOKEN env var if not provided)
 * @returns Authentication result with user info or null if not authenticated
 */
export async function getUser(token?: string): Promise<AuthResult> {
	const config = getConfig()
	const authToken = token || getEnv('DO_TOKEN') || ''

	if (!authToken) {
		return { user: null }
	}

	try {
		const response = await config.fetch(`${config.apiUrl}/me`, {
			method: 'GET',
			headers: {
				'Authorization': `Bearer ${authToken}`,
				'Content-Type': 'application/json',
			},
		})

		if (!response.ok) {
			if (response.status === 401) {
				return { user: null }
			}
			throw new Error(`Authentication failed: ${response.statusText}`)
		}

		const user = (await response.json()) as User
		return { user, token: authToken }
	} catch (error) {
		console.error('Auth error:', error)
		return { user: null }
	}
}

/**
 * Initiate login flow
 * Calls POST /login endpoint
 *
 * @param credentials - Login credentials (email, password, etc.)
 * @returns Authentication result with user info and token
 */
export async function login(credentials: {
	email?: string
	password?: string
	[key: string]: any
}): Promise<AuthResult> {
	const config = getConfig()

	try {
		const response = await config.fetch(`${config.apiUrl}/login`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
			},
			body: JSON.stringify(credentials),
		})

		if (!response.ok) {
			throw new Error(`Login failed: ${response.statusText}`)
		}

		const data = (await response.json()) as { user: User; token: string }
		return { user: data.user, token: data.token }
	} catch (error) {
		console.error('Login error:', error)
		throw error
	}
}

/**
 * Logout current user
 * Calls POST /logout endpoint
 *
 * @param token - Optional authentication token (will use DO_TOKEN env var if not provided)
 */
export async function logout(token?: string): Promise<void> {
	const config = getConfig()
	const authToken = token || getEnv('DO_TOKEN') || ''

	if (!authToken) {
		return
	}

	try {
		const response = await config.fetch(`${config.apiUrl}/logout`, {
			method: 'POST',
			headers: {
				'Authorization': `Bearer ${authToken}`,
				'Content-Type': 'application/json',
			},
		})

		if (!response.ok) {
			console.warn(`Logout warning: ${response.statusText}`)
		}
	} catch (error) {
		console.error('Logout error:', error)
	}
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
 * Get token from environment or stored credentials
 *
 * Checks in order:
 * 1. globalThis.DO_ADMIN_TOKEN / DO_TOKEN (Workers legacy)
 * 2. process.env.DO_ADMIN_TOKEN / DO_TOKEN (Node.js)
 * 3. cloudflare:workers env import (Workers 2025+) - supports secrets store bindings
 * 4. Stored token (keychain/secure file) - with automatic refresh if expired
 *
 * @see https://developers.cloudflare.com/changelog/2025-03-17-importable-env/
 */
export async function getToken(): Promise<string | null> {
	// Check env vars first (globalThis for Workers legacy, process.env for Node)
	const adminToken = getEnv('DO_ADMIN_TOKEN')
	if (adminToken) return adminToken
	const doToken = getEnv('DO_TOKEN')
	if (doToken) return doToken

	// Try cloudflare:workers env import (Workers 2025+)
	// Supports both plain strings and secrets store bindings
	try {
		// @ts-ignore - cloudflare:workers only available in Workers runtime
		const { env } = await import('cloudflare:workers')

		const cfAdminToken = await resolveSecret((env as any).DO_ADMIN_TOKEN)
		if (cfAdminToken) return cfAdminToken

		const cfToken = await resolveSecret((env as any).DO_TOKEN)
		if (cfToken) return cfToken
	} catch {
		// Not in Workers environment or env not available
	}

	// Try stored token (Node.js only - uses keychain/file storage)
	try {
		const { createSecureStorage } = await import('./storage.js')
		const config = getConfig()
		const storage = createSecureStorage(config.storagePath)

		// Get full token data if available
		const tokenData = storage.getTokenData ? await storage.getTokenData() : null

		if (tokenData) {
			// If token is not expired, return it
			if (!isTokenExpired(tokenData.expiresAt)) {
				return tokenData.accessToken
			}

			// Token is expired - try to refresh if we have a refresh token
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

					return newTokens.access_token
				} catch {
					// Refresh failed - return null (caller should re-authenticate)
					return null
				}
			}

			// Expired but no refresh token - return null
			return null
		}

		// Fall back to simple token storage (no expiration tracking)
		return await storage.getToken()
	} catch {
		// Storage not available (browser/worker) - return null
		return null
	}
}

/**
 * Check if user is authenticated (has valid token)
 */
export async function isAuthenticated(token?: string): Promise<boolean> {
	const result = await getUser(token)
	return result.user !== null
}

/**
 * Auth provider function type for HTTP clients
 */
export type AuthProvider = () => string | null | undefined | Promise<string | null | undefined>

/**
 * Create an auth provider function for HTTP clients (apis.do, rpc.do)
 * Returns a function that resolves to a token string
 *
 * @example
 * import { auth } from 'oauth.do'
 * const getAuth = auth()
 * const token = await getAuth()
 */
export function auth(): AuthProvider {
	return getToken
}

/**
 * Refresh an access token using a refresh token
 *
 * @param refreshToken - The refresh token from the original auth response
 * @returns New token response with fresh access_token (and possibly new refresh_token)
 */
export async function refreshAccessToken(refreshToken: string): Promise<TokenResponse> {
	const config = getConfig()

	if (!config.clientId) {
		throw new Error('Client ID is required for token refresh')
	}

	const response = await config.fetch('https://auth.apis.do/user_management/authenticate', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded',
		},
		body: new URLSearchParams({
			grant_type: 'refresh_token',
			refresh_token: refreshToken,
			client_id: config.clientId,
		}).toString(),
	})

	if (!response.ok) {
		const errorText = await response.text()
		throw new Error(`Token refresh failed: ${response.status} - ${errorText}`)
	}

	return (await response.json()) as TokenResponse
}

/**
 * Get stored token data from storage
 */
export async function getStoredTokenData(): Promise<StoredTokenData | null> {
	try {
		const { createSecureStorage } = await import('./storage.js')
		const config = getConfig()
		const storage = createSecureStorage(config.storagePath)
		if (storage.getTokenData) {
			return await storage.getTokenData()
		}
		// Fall back to just access token
		const token = await storage.getToken()
		return token ? { accessToken: token } : null
	} catch {
		return null
	}
}

/**
 * Store token data including refresh token
 */
export async function storeTokenData(data: StoredTokenData): Promise<void> {
	try {
		const { createSecureStorage } = await import('./storage.js')
		const config = getConfig()
		const storage = createSecureStorage(config.storagePath)
		if (storage.setTokenData) {
			await storage.setTokenData(data)
		} else {
			await storage.setToken(data.accessToken)
		}
	} catch (error) {
		console.error('Failed to store token data:', error)
		throw error
	}
}

/**
 * Build OAuth authorization URL
 *
 * @example
 * const url = buildAuthUrl({
 *   redirectUri: 'https://myapp.com/callback',
 *   scope: 'openid profile email',
 * })
 */
export function buildAuthUrl(options: {
	redirectUri: string
	scope?: string
	state?: string
	responseType?: string
	clientId?: string
	authDomain?: string
}): string {
	const config = getConfig()
	const clientId = options.clientId || config.clientId
	const authDomain = options.authDomain || config.authKitDomain

	const params = new URLSearchParams({
		client_id: clientId,
		redirect_uri: options.redirectUri,
		response_type: options.responseType || 'code',
		scope: options.scope || 'openid profile email',
	})

	if (options.state) {
		params.set('state', options.state)
	}

	return `https://${authDomain}/authorize?${params.toString()}`
}
