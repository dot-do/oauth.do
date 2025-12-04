import type { OAuthConfig } from './types.js'

/**
 * Global OAuth configuration
 */
let globalConfig: Required<OAuthConfig> = {
	apiUrl: process.env.OAUTH_API_URL || process.env.API_URL || 'https://apis.do',
	clientId: process.env.OAUTH_CLIENT_ID || 'oauth.do',
	authKitDomain: process.env.OAUTH_AUTHKIT_DOMAIN || 'login.oauth.do',
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
