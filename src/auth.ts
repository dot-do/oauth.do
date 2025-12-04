import { getConfig } from './config.js'
import type { User, AuthResult } from './types.js'

/**
 * Get current authenticated user
 * Calls GET /me endpoint
 *
 * @param token - Optional authentication token (will use DO_TOKEN env var if not provided)
 * @returns Authentication result with user info or null if not authenticated
 */
export async function auth(token?: string): Promise<AuthResult> {
	const config = getConfig()
	const authToken = token || process.env.DO_TOKEN || ''

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
	const authToken = token || process.env.DO_TOKEN || ''

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

/**
 * Get token from environment
 */
export function getToken(): string | null {
	return process.env.DO_TOKEN || null
}

/**
 * Check if user is authenticated (has valid token)
 */
export async function isAuthenticated(token?: string): Promise<boolean> {
	const result = await auth(token)
	return result.user !== null
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
