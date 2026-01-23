import type { OAuthConfig } from './types.js'
import { getEnv } from './utils.js'

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
