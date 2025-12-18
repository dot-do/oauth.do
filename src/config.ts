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
 * Note: storagePath is optional and may be undefined
 */
let globalConfig: Omit<Required<OAuthConfig>, 'storagePath'> & Pick<OAuthConfig, 'storagePath'> = {
	apiUrl: getEnv('OAUTH_API_URL') || getEnv('API_URL') || 'https://apis.do',
	clientId: getEnv('OAUTH_CLIENT_ID') || 'client_01JQYTRXK9ZPD8JPJTKDCRB656',
	authKitDomain: getEnv('OAUTH_AUTHKIT_DOMAIN') || 'login.oauth.do',
	fetch: globalThis.fetch,
	storagePath: getEnv('OAUTH_STORAGE_PATH'),
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
export function getConfig(): Omit<Required<OAuthConfig>, 'storagePath'> & Pick<OAuthConfig, 'storagePath'> {
	return globalConfig
}
