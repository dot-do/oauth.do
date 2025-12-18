import type { TokenStorage, StoredTokenData } from './types.js'

// Keychain service and account identifiers
const KEYCHAIN_SERVICE = 'oauth.do'
const KEYCHAIN_ACCOUNT = 'access_token'

/**
 * Check if we're running in a Node.js environment
 */
function isNode(): boolean {
	return typeof process !== 'undefined' &&
		process.versions != null &&
		process.versions.node != null
}

/**
 * Safe environment variable access
 */
function getEnv(key: string): string | undefined {
	if (typeof process !== 'undefined' && process.env?.[key]) return process.env[key]
	return undefined
}

/**
 * Keychain-based token storage using OS credential manager
 * - macOS: Keychain
 * - Windows: Credential Manager
 * - Linux: Secret Service (libsecret)
 *
 * This is the most secure option for CLI token storage.
 */
export class KeychainTokenStorage implements TokenStorage {
	private keytar: typeof import('keytar') | null = null
	private initialized = false

	/**
	 * Lazily load keytar module
	 * Returns null if keytar is not available (e.g., missing native dependencies)
	 */
	private async getKeytar(): Promise<typeof import('keytar') | null> {
		if (this.initialized) {
			return this.keytar
		}

		this.initialized = true

		try {
			// Dynamic import to handle cases where keytar native module isn't available
			const imported = await import('keytar')
			// Handle ESM/CJS interop - keytar is CommonJS, so functions may be on .default
			const keytarModule = (imported as any).default || imported
			this.keytar = keytarModule as typeof import('keytar')

			// Verify the module loaded correctly by checking for expected function
			if (typeof this.keytar.getPassword !== 'function') {
				if (getEnv('DEBUG')) {
					console.warn('Keytar module loaded but getPassword is not a function:', Object.keys(this.keytar))
				}
				this.keytar = null
				return null
			}

			return this.keytar
		} catch (error) {
			// keytar requires native dependencies that may not be available
			// Fall back gracefully
			if (getEnv('DEBUG')) {
				console.warn('Keychain storage not available:', error)
			}
			return null
		}
	}

	async getToken(): Promise<string | null> {
		const keytar = await this.getKeytar()
		if (!keytar) {
			return null
		}

		try {
			const token = await keytar.getPassword(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
			return token
		} catch (error) {
			if (getEnv('DEBUG')) {
				console.warn('Failed to get token from keychain:', error)
			}
			return null
		}
	}

	async setToken(token: string): Promise<void> {
		try {
			const keytar = await this.getKeytar()
			if (!keytar) {
				throw new Error('Keychain storage not available')
			}

			await keytar.setPassword(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, token)
		} catch (error: any) {
			// Check if this is a native module error vs an actual keychain error
			if (error?.code === 'MODULE_NOT_FOUND' || error?.message?.includes('Cannot find module')) {
				throw new Error('Keychain storage not available: native module not built')
			}
			throw new Error(`Failed to save token to keychain: ${error}`)
		}
	}

	async removeToken(): Promise<void> {
		const keytar = await this.getKeytar()
		if (!keytar) {
			return
		}

		try {
			await keytar.deletePassword(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
		} catch {
			// Ignore errors if credential doesn't exist
		}
	}

	/**
	 * Check if keychain storage is available on this system
	 */
	async isAvailable(): Promise<boolean> {
		try {
			const keytar = await this.getKeytar()
			if (!keytar) {
				return false
			}

			// Try a read operation to verify keychain access
			// This will throw if native module is not built
			await keytar.getPassword(KEYCHAIN_SERVICE, '__test__')
			return true
		} catch (error) {
			if (getEnv('DEBUG')) {
				console.warn('Keychain not available:', error)
			}
			return false
		}
	}
}

/**
 * Secure file-based token storage for CLI
 * Stores token in ~/.oauth.do/token with restricted permissions (0600)
 *
 * This is the default storage for Node.js CLI because it doesn't require
 * GUI authorization popups like the keychain does on macOS.
 * Only works in Node.js environment.
 */
export class SecureFileTokenStorage implements TokenStorage {
	private tokenPath: string | null = null
	private configDir: string | null = null
	private initialized = false
	private customPath?: string

	constructor(customPath?: string) {
		this.customPath = customPath
	}

	private async init(): Promise<boolean> {
		if (this.initialized) return this.tokenPath !== null
		this.initialized = true

		if (!isNode()) return false

		try {
			const os = await import('os')
			const path = await import('path')

			// Use custom path if provided
			if (this.customPath) {
				// Expand ~ to home directory
				const expandedPath = this.customPath.startsWith('~/')
					? path.join(os.homedir(), this.customPath.slice(2))
					: this.customPath

				this.tokenPath = expandedPath
				this.configDir = path.dirname(expandedPath)
			} else {
				// Default path
				this.configDir = path.join(os.homedir(), '.oauth.do')
				this.tokenPath = path.join(this.configDir, 'token')
			}
			return true
		} catch {
			return false
		}
	}

	async getToken(): Promise<string | null> {
		// Try to get from token data first (new format)
		const data = await this.getTokenData()
		if (data) {
			return data.accessToken
		}

		// Fall back to legacy plain text format
		if (!(await this.init()) || !this.tokenPath) return null

		try {
			const fs = await import('fs/promises')
			const stats = await fs.stat(this.tokenPath)
			const mode = stats.mode & 0o777

			if (mode !== 0o600 && getEnv('DEBUG')) {
				console.warn(
					`Warning: Token file has insecure permissions (${mode.toString(8)}). ` +
						`Expected 600. Run: chmod 600 ${this.tokenPath}`
				)
			}

			const content = await fs.readFile(this.tokenPath, 'utf-8')
			const trimmed = content.trim()

			// Check if it's JSON (new format) or plain token (legacy)
			if (trimmed.startsWith('{')) {
				const data = JSON.parse(trimmed) as StoredTokenData
				return data.accessToken
			}

			return trimmed
		} catch {
			return null
		}
	}

	async setToken(token: string): Promise<void> {
		// Store as token data for consistency, trimming whitespace
		await this.setTokenData({ accessToken: token.trim() })
	}

	async getTokenData(): Promise<StoredTokenData | null> {
		if (!(await this.init()) || !this.tokenPath) return null

		try {
			const fs = await import('fs/promises')
			const content = await fs.readFile(this.tokenPath, 'utf-8')
			const trimmed = content.trim()

			// Check if it's JSON format
			if (trimmed.startsWith('{')) {
				return JSON.parse(trimmed) as StoredTokenData
			}

			// Legacy plain text format - convert to token data
			return { accessToken: trimmed }
		} catch {
			return null
		}
	}

	async setTokenData(data: StoredTokenData): Promise<void> {
		if (!(await this.init()) || !this.tokenPath || !this.configDir) {
			throw new Error('File storage not available')
		}

		try {
			const fs = await import('fs/promises')
			await fs.mkdir(this.configDir, { recursive: true, mode: 0o700 })
			await fs.writeFile(this.tokenPath, JSON.stringify(data), { encoding: 'utf-8', mode: 0o600 })
			await fs.chmod(this.tokenPath, 0o600)
		} catch (error) {
			console.error('Failed to save token data:', error)
			throw error
		}
	}

	async removeToken(): Promise<void> {
		if (!(await this.init()) || !this.tokenPath) return

		try {
			const fs = await import('fs/promises')
			await fs.unlink(this.tokenPath)
		} catch {
			// Ignore errors if file doesn't exist
		}
	}

	/**
	 * Get information about the storage backend
	 */
	async getStorageInfo(): Promise<{ type: 'file'; secure: boolean; path: string | null }> {
		await this.init()
		return { type: 'file', secure: true, path: this.tokenPath }
	}
}

/**
 * File-based token storage for CLI (legacy, less secure)
 * Stores token in ~/.oauth.do/token
 * Only works in Node.js environment.
 *
 * @deprecated Use SecureFileTokenStorage or KeychainTokenStorage instead
 */
export class FileTokenStorage implements TokenStorage {
	private tokenPath: string | null = null
	private configDir: string | null = null
	private initialized = false

	private async init(): Promise<boolean> {
		if (this.initialized) return this.tokenPath !== null
		this.initialized = true

		if (!isNode()) return false

		try {
			const os = await import('os')
			const path = await import('path')
			this.configDir = path.join(os.homedir(), '.oauth.do')
			this.tokenPath = path.join(this.configDir, 'token')
			return true
		} catch {
			return false
		}
	}

	async getToken(): Promise<string | null> {
		if (!(await this.init()) || !this.tokenPath) return null

		try {
			const fs = await import('fs/promises')
			const token = await fs.readFile(this.tokenPath, 'utf-8')
			return token.trim()
		} catch {
			return null
		}
	}

	async setToken(token: string): Promise<void> {
		if (!(await this.init()) || !this.tokenPath || !this.configDir) {
			throw new Error('File storage not available')
		}

		try {
			const fs = await import('fs/promises')
			await fs.mkdir(this.configDir, { recursive: true })
			await fs.writeFile(this.tokenPath, token, 'utf-8')
		} catch (error) {
			console.error('Failed to save token:', error)
			throw error
		}
	}

	async removeToken(): Promise<void> {
		if (!(await this.init()) || !this.tokenPath) return

		try {
			const fs = await import('fs/promises')
			await fs.unlink(this.tokenPath)
		} catch {
			// Ignore errors if file doesn't exist
		}
	}
}

/**
 * In-memory token storage (for browser or testing)
 */
export class MemoryTokenStorage implements TokenStorage {
	private token: string | null = null

	async getToken(): Promise<string | null> {
		return this.token
	}

	async setToken(token: string): Promise<void> {
		this.token = token
	}

	async removeToken(): Promise<void> {
		this.token = null
	}
}

/**
 * LocalStorage-based token storage (for browser)
 */
export class LocalStorageTokenStorage implements TokenStorage {
	private key = 'oauth.do:token'

	async getToken(): Promise<string | null> {
		if (typeof localStorage === 'undefined') {
			return null
		}
		return localStorage.getItem(this.key)
	}

	async setToken(token: string): Promise<void> {
		if (typeof localStorage === 'undefined') {
			throw new Error('localStorage is not available')
		}
		localStorage.setItem(this.key, token)
	}

	async removeToken(): Promise<void> {
		if (typeof localStorage === 'undefined') {
			return
		}
		localStorage.removeItem(this.key)
	}
}

/**
 * Composite token storage that tries multiple storage backends
 * Attempts keychain first, then falls back to secure file storage
 */
export class CompositeTokenStorage implements TokenStorage {
	private keychainStorage: KeychainTokenStorage
	private fileStorage: SecureFileTokenStorage
	private preferredStorage: TokenStorage | null = null

	constructor() {
		this.keychainStorage = new KeychainTokenStorage()
		this.fileStorage = new SecureFileTokenStorage()
	}

	/**
	 * Determine the best available storage backend
	 */
	private async getPreferredStorage(): Promise<TokenStorage> {
		if (this.preferredStorage) {
			return this.preferredStorage
		}

		// Try keychain first
		if (await this.keychainStorage.isAvailable()) {
			this.preferredStorage = this.keychainStorage
			return this.preferredStorage
		}

		// Fall back to secure file storage
		this.preferredStorage = this.fileStorage
		return this.preferredStorage
	}

	async getToken(): Promise<string | null> {
		// First, check keychain
		const keychainToken = await this.keychainStorage.getToken()
		if (keychainToken) {
			return keychainToken
		}

		// Fall back to file storage (for migration from old installations)
		const fileToken = await this.fileStorage.getToken()
		if (fileToken) {
			// Migrate token to keychain if available
			if (await this.keychainStorage.isAvailable()) {
				try {
					await this.keychainStorage.setToken(fileToken)
					await this.fileStorage.removeToken()
					if (getEnv('DEBUG')) {
						console.log('Migrated token from file to keychain')
					}
				} catch {
					// Continue with file token if migration fails
				}
			}
			return fileToken
		}

		return null
	}

	async setToken(token: string): Promise<void> {
		const storage = await this.getPreferredStorage()
		await storage.setToken(token)
	}

	async removeToken(): Promise<void> {
		// Remove from both storages to ensure complete logout
		await Promise.all([this.keychainStorage.removeToken(), this.fileStorage.removeToken()])
	}

	/**
	 * Get information about the current storage backend
	 */
	async getStorageInfo(): Promise<{ type: 'keychain' | 'file'; secure: boolean }> {
		if (await this.keychainStorage.isAvailable()) {
			return { type: 'keychain', secure: true }
		}
		return { type: 'file', secure: true }
	}
}

/**
 * Create the default token storage
 * - Node.js: Uses secure file storage (~/.oauth.do/token with 0600 permissions)
 * - Browser: Uses localStorage
 * - Worker: Uses in-memory storage (tokens should be passed via env bindings)
 *
 * Note: We use file storage by default because keychain storage on macOS
 * requires GUI authorization popups, which breaks automation and agent workflows.
 *
 * @param storagePath - Optional custom path for token storage (e.g., '~/.studio/tokens.json')
 */
export function createSecureStorage(storagePath?: string): TokenStorage {
	// Node.js - use secure file storage (no keychain popups)
	if (isNode()) {
		return new SecureFileTokenStorage(storagePath)
	}

	// Browser - use localStorage
	if (typeof localStorage !== 'undefined') {
		return new LocalStorageTokenStorage()
	}

	// Workers/other - use memory storage
	return new MemoryTokenStorage()
}
