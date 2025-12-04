import { homedir } from 'os'
import { join } from 'path'
import { readFile, writeFile, unlink, mkdir, chmod, stat } from 'fs/promises'
import type { TokenStorage } from './types.js'

// Keychain service and account identifiers
const KEYCHAIN_SERVICE = 'oauth.do'
const KEYCHAIN_ACCOUNT = 'access_token'

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
			this.keytar = await import('keytar')
			return this.keytar
		} catch (error) {
			// keytar requires native dependencies that may not be available
			// Fall back gracefully
			if (process.env.DEBUG) {
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
			if (process.env.DEBUG) {
				console.warn('Failed to get token from keychain:', error)
			}
			return null
		}
	}

	async setToken(token: string): Promise<void> {
		const keytar = await this.getKeytar()
		if (!keytar) {
			throw new Error('Keychain storage not available')
		}

		try {
			await keytar.setPassword(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, token)
		} catch (error) {
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
		const keytar = await this.getKeytar()
		if (!keytar) {
			return false
		}

		try {
			// Try a read operation to verify keychain access
			await keytar.getPassword(KEYCHAIN_SERVICE, '__test__')
			return true
		} catch {
			return false
		}
	}
}

/**
 * Secure file-based token storage for CLI
 * Stores token in ~/.oauth.do/token with restricted permissions (0600)
 *
 * This is used as a fallback when keychain storage is not available.
 */
export class SecureFileTokenStorage implements TokenStorage {
	private tokenPath: string
	private configDir: string

	constructor() {
		this.configDir = join(homedir(), '.oauth.do')
		this.tokenPath = join(this.configDir, 'token')
	}

	async getToken(): Promise<string | null> {
		try {
			// Verify file permissions before reading
			const stats = await stat(this.tokenPath)
			const mode = stats.mode & 0o777

			// Warn if file has insecure permissions
			if (mode !== 0o600 && process.env.DEBUG) {
				console.warn(
					`Warning: Token file has insecure permissions (${mode.toString(8)}). ` +
						`Expected 600. Run: chmod 600 ${this.tokenPath}`
				)
			}

			const token = await readFile(this.tokenPath, 'utf-8')
			return token.trim()
		} catch {
			return null
		}
	}

	async setToken(token: string): Promise<void> {
		try {
			// Create config directory with restricted permissions
			await mkdir(this.configDir, { recursive: true, mode: 0o700 })

			// Write token file
			await writeFile(this.tokenPath, token, { encoding: 'utf-8', mode: 0o600 })

			// Ensure permissions are correct (writeFile mode may be affected by umask)
			await chmod(this.tokenPath, 0o600)
		} catch (error) {
			console.error('Failed to save token:', error)
			throw error
		}
	}

	async removeToken(): Promise<void> {
		try {
			await unlink(this.tokenPath)
		} catch {
			// Ignore errors if file doesn't exist
		}
	}
}

/**
 * File-based token storage for CLI (legacy, less secure)
 * Stores token in ~/.oauth.do/token
 *
 * @deprecated Use SecureFileTokenStorage or KeychainTokenStorage instead
 */
export class FileTokenStorage implements TokenStorage {
	private tokenPath: string

	constructor() {
		const configDir = join(homedir(), '.oauth.do')
		this.tokenPath = join(configDir, 'token')
	}

	async getToken(): Promise<string | null> {
		try {
			const token = await readFile(this.tokenPath, 'utf-8')
			return token.trim()
		} catch {
			return null
		}
	}

	async setToken(token: string): Promise<void> {
		try {
			const configDir = join(homedir(), '.oauth.do')
			await mkdir(configDir, { recursive: true })
			await writeFile(this.tokenPath, token, 'utf-8')
		} catch (error) {
			console.error('Failed to save token:', error)
			throw error
		}
	}

	async removeToken(): Promise<void> {
		try {
			await unlink(this.tokenPath)
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
					if (process.env.DEBUG) {
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
 * Create the default token storage for CLI use
 * Uses OS keychain when available, falls back to secure file storage
 */
export function createSecureStorage(): TokenStorage {
	return new CompositeTokenStorage()
}
