import type { OAuthConfig } from './types.js'
import { CANONICAL_API_ORIGIN, CANONICAL_AUTHKIT_DOMAIN } from 'id.org.ai/auth'
import { getEnv } from './utils.js'

/**
 * Global OAuth configuration
 * Note: storagePath is optional and may be undefined
 */
let globalConfig: Omit<Required<OAuthConfig>, 'storagePath'> & Pick<OAuthConfig, 'storagePath'> = {
  apiUrl: getEnv('OAUTH_API_URL') || getEnv('API_URL') || CANONICAL_API_ORIGIN,
  clientId: getEnv('OAUTH_CLIENT_ID') || 'client_01JQYTRXK9ZPD8JPJTKDCRB656',
  authKitDomain: getEnv('OAUTH_AUTHKIT_DOMAIN') || CANONICAL_AUTHKIT_DOMAIN,
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
