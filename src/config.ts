import type { OAuthConfig } from './types.js'

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
 * Global OAuth configuration
 */
let globalConfig: Required<OAuthConfig> = {
	apiUrl: getEnv('OAUTH_API_URL') || getEnv('API_URL') || 'https://apis.do',
	clientId: getEnv('OAUTH_CLIENT_ID') || 'oauth.do',
	authKitDomain: getEnv('OAUTH_AUTHKIT_DOMAIN') || 'login.oauth.do',
	fetch: globalThis.fetch,
}

/**
 * Configure OAuth settings
 */
export function configure(config: OAuthConfig): void {
	globalConfig = {
		...globalConfig,
		...config,
	}
}

/**
 * Get current configuration
 */
export function getConfig(): Required<OAuthConfig> {
	return globalConfig
}
