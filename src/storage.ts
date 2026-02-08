import type { TokenStorage, StoredTokenData } from './types.js'
import { getEnv } from './utils.js'

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

// ─── File Locking & Atomic Writes ─────────────────────────────────────────────
//
// Multiple concurrent CLI commands (e.g. `oauth.do token` + `oauth.do login`)
// can read/write the token file simultaneously, causing corruption or lost tokens.
//
// Solution:
//  1. Advisory file locking via lockfiles (`.lock` suffix)
//  2. Atomic writes via temp file + rename
//  3. Retry with exponential back-off when lock acquisition fails
//  4. Stale lock detection (locks older than LOCK_STALE_MS are forcefully removed)
// ──────────────────────────────────────────────────────────────────────────────

/** How long (ms) before a lockfile is considered stale and can be forcefully removed */
const LOCK_STALE_MS = 10_000

/** Maximum number of attempts to acquire a lock */
const LOCK_RETRIES = 5

/** Base delay (ms) between lock acquisition retries (doubled each attempt with jitter) */
const LOCK_RETRY_DELAY_MS = 50

/**
 * Acquire an advisory file lock by creating a lockfile with O_EXCL (exclusive create).
 * Returns a release function. Includes retry with exponential back-off and stale lock cleanup.
 */
async function acquireFileLock(lockPath: string): Promise<() => Promise<void>> {
	const fs = await import('fs/promises')
	const path = await import('path')
	const lockContent = JSON.stringify({ pid: process.pid, ts: Date.now() })

	// Ensure the parent directory of the lockfile exists
	const lockDir = path.dirname(lockPath)
	await fs.mkdir(lockDir, { recursive: true, mode: 0o700 })

	for (let attempt = 0; attempt < LOCK_RETRIES; attempt++) {
		try {
			// O_EXCL + O_CREAT: fails if the file already exists — atomic "create if absent"
			const fd = await fs.open(lockPath, 'wx')
			await fd.writeFile(lockContent, 'utf-8')
			await fd.close()

			// Return a release function
			return async () => {
				try {
					await fs.unlink(lockPath)
				} catch {
					// Ignore — lockfile may have been cleaned up already
				}
			}
		} catch (err: unknown) {
			const code = (err as NodeJS.ErrnoException)?.code
			if (code !== 'EEXIST') {
				// Unexpected error — propagate
				throw err
			}

			// Lock file exists — check if it's stale
			try {
				const stat = await fs.stat(lockPath)
				const age = Date.now() - stat.mtimeMs
				if (age > LOCK_STALE_MS) {
					// Stale lock from a crashed process — remove and retry immediately
					if (getEnv('DEBUG')) {
						console.warn(`Removing stale lockfile (age: ${age}ms): ${lockPath}`)
					}
					try {
						await fs.unlink(lockPath)
					} catch {
						// Another process may have already cleaned it up
					}
					continue // Retry immediately without waiting
				}
			} catch {
				// Can't stat the lock — it may have been released between the open() and stat()
				continue
			}

			// Lock is held by another live process — wait with exponential back-off + jitter
			if (attempt < LOCK_RETRIES - 1) {
				const delay = LOCK_RETRY_DELAY_MS * Math.pow(2, attempt) + Math.random() * LOCK_RETRY_DELAY_MS
				await new Promise<void>((resolve) => setTimeout(resolve, delay))
			}
		}
	}

	throw new Error(`Failed to acquire file lock after ${LOCK_RETRIES} attempts: ${lockPath}`)
}

/**
 * Write a file atomically by writing to a temporary sibling file and then renaming.
 * `rename()` is atomic on POSIX systems, so readers never see a half-written file.
 *
 * @param filePath - The target file path
 * @param content  - The content to write
 * @param mode     - File permission mode (default: 0o600)
 */
async function atomicWriteFile(filePath: string, content: string, mode = 0o600): Promise<void> {
	const fs = await import('fs/promises')
	const path = await import('path')
	const crypto = await import('crypto')

	// Write to a temp file in the same directory (same filesystem = atomic rename)
	const tmpSuffix = crypto.randomBytes(6).toString('hex')
	const tmpPath = path.join(path.dirname(filePath), `.token.tmp.${tmpSuffix}`)

	try {
		await fs.writeFile(tmpPath, content, { encoding: 'utf-8', mode })
		await fs.rename(tmpPath, filePath)
		// Ensure permissions after rename (some systems may not preserve mode across rename)
		await fs.chmod(filePath, mode)
	} catch (error) {
		// Clean up temp file on failure
		try {
			await fs.unlink(tmpPath)
		} catch {
			// Ignore cleanup errors
		}
		throw error
	}
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
			const keytarModule = (imported as Record<string, unknown>).default || imported
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
		} catch (error: unknown) {
			// Check if this is a native module error vs an actual keychain error
			const err = error instanceof Error ? error : null
			if ((error as Record<string, unknown>)?.code === 'MODULE_NOT_FOUND' || err?.message?.includes('Cannot find module')) {
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

	async getTokenData(): Promise<StoredTokenData | null> {
		const keytar = await this.getKeytar()
		if (!keytar) {
			return null
		}

		try {
			const stored = await keytar.getPassword(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
			if (!stored) {
				return null
			}

			// Check if it's JSON format (new format with refresh token)
			if (stored.startsWith('{')) {
				return JSON.parse(stored) as StoredTokenData
			}

			// Legacy plain text format - convert to token data
			return { accessToken: stored }
		} catch (error) {
			if (getEnv('DEBUG')) {
				console.warn('Failed to get token data from keychain:', error)
			}
			return null
		}
	}

	async setTokenData(data: StoredTokenData): Promise<void> {
		const keytar = await this.getKeytar()
		if (!keytar) {
			throw new Error('Keychain storage not available')
		}

		try {
			// Store as JSON to preserve refresh token and expiration
			await keytar.setPassword(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, JSON.stringify(data))
		} catch (error: unknown) {
			const err = error instanceof Error ? error : null
			if ((error as Record<string, unknown>)?.code === 'MODULE_NOT_FOUND' || err?.message?.includes('Cannot find module')) {
				throw new Error('Keychain storage not available: native module not built')
			}
			throw new Error(`Failed to save token data to keychain: ${error}`)
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
 * Uses atomic writes (write-to-temp-then-rename) and advisory file locking
 * to prevent corruption from concurrent CLI commands.
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

	/** Get the lockfile path for advisory file locking */
	private getLockPath(): string {
		return `${this.tokenPath}.lock`
	}

	async getToken(): Promise<string | null> {
		// Try to get from token data first (new format)
		const data = await this.getTokenData()
		if (data) {
			return data.accessToken
		}

		// Fall back to legacy plain text format
		if (!(await this.init()) || !this.tokenPath) return null

		const release = await acquireFileLock(this.getLockPath())
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
		} finally {
			await release()
		}
	}

	async setToken(token: string): Promise<void> {
		// Store as token data for consistency, trimming whitespace
		await this.setTokenData({ accessToken: token.trim() })
	}

	async getTokenData(): Promise<StoredTokenData | null> {
		if (!(await this.init()) || !this.tokenPath) return null

		const release = await acquireFileLock(this.getLockPath())
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
		} finally {
			await release()
		}
	}

	async setTokenData(data: StoredTokenData): Promise<void> {
		if (!(await this.init()) || !this.tokenPath || !this.configDir) {
			throw new Error('File storage not available')
		}

		const release = await acquireFileLock(this.getLockPath())
		try {
			const fs = await import('fs/promises')
			await fs.mkdir(this.configDir, { recursive: true, mode: 0o700 })
			await atomicWriteFile(this.tokenPath, JSON.stringify(data), 0o600)
		} catch (error) {
			console.error('Failed to save token data:', error)
			throw error
		} finally {
			await release()
		}
	}

	async removeToken(): Promise<void> {
		if (!(await this.init()) || !this.tokenPath) return

		const release = await acquireFileLock(this.getLockPath())
		try {
			const fs = await import('fs/promises')
			await fs.unlink(this.tokenPath)
		} catch {
			// Ignore errors if file doesn't exist
		} finally {
			await release()
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
 * Uses atomic writes and advisory file locking to prevent corruption
 * from concurrent CLI commands.
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

	/** Get the lockfile path for advisory file locking */
	private getLockPath(): string {
		return `${this.tokenPath}.lock`
	}

	async getToken(): Promise<string | null> {
		if (!(await this.init()) || !this.tokenPath) return null

		const release = await acquireFileLock(this.getLockPath())
		try {
			const fs = await import('fs/promises')
			const token = await fs.readFile(this.tokenPath, 'utf-8')
			return token.trim()
		} catch {
			return null
		} finally {
			await release()
		}
	}

	async setToken(token: string): Promise<void> {
		if (!(await this.init()) || !this.tokenPath || !this.configDir) {
			throw new Error('File storage not available')
		}

		const release = await acquireFileLock(this.getLockPath())
		try {
			const fs = await import('fs/promises')
			await fs.mkdir(this.configDir, { recursive: true })
			await atomicWriteFile(this.tokenPath, token)
		} catch (error) {
			console.error('Failed to save token:', error)
			throw error
		} finally {
			await release()
		}
	}

	async removeToken(): Promise<void> {
		if (!(await this.init()) || !this.tokenPath) return

		const release = await acquireFileLock(this.getLockPath())
		try {
			const fs = await import('fs/promises')
			await fs.unlink(this.tokenPath)
		} catch {
			// Ignore errors if file doesn't exist
		} finally {
			await release()
		}
	}
}

/**
 * In-memory token storage (for browser or testing)
 */
export class MemoryTokenStorage implements TokenStorage {
	private tokenData: StoredTokenData | null = null

	async getToken(): Promise<string | null> {
		return this.tokenData?.accessToken ?? null
	}

	async setToken(token: string): Promise<void> {
		this.tokenData = { accessToken: token }
	}

	async removeToken(): Promise<void> {
		this.tokenData = null
	}

	async getTokenData(): Promise<StoredTokenData | null> {
		return this.tokenData
	}

	async setTokenData(data: StoredTokenData): Promise<void> {
		this.tokenData = data
	}
}

/**
 * LocalStorage-based token storage (for browser)
 */
export class LocalStorageTokenStorage implements TokenStorage {
	private key = 'oauth.do:token'

	async getToken(): Promise<string | null> {
		const data = await this.getTokenData()
		return data?.accessToken ?? null
	}

	async setToken(token: string): Promise<void> {
		await this.setTokenData({ accessToken: token })
	}

	async removeToken(): Promise<void> {
		if (typeof localStorage === 'undefined') {
			return
		}
		localStorage.removeItem(this.key)
	}

	async getTokenData(): Promise<StoredTokenData | null> {
		if (typeof localStorage === 'undefined') {
			return null
		}
		const stored = localStorage.getItem(this.key)
		if (!stored) {
			return null
		}
		// Check if it's JSON format
		if (stored.startsWith('{')) {
			return JSON.parse(stored) as StoredTokenData
		}
		// Legacy plain text format
		return { accessToken: stored }
	}

	async setTokenData(data: StoredTokenData): Promise<void> {
		if (typeof localStorage === 'undefined') {
			throw new Error('localStorage is not available')
		}
		localStorage.setItem(this.key, JSON.stringify(data))
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

	async getTokenData(): Promise<StoredTokenData | null> {
		// First, check keychain
		const keychainData = await this.keychainStorage.getTokenData()
		if (keychainData) {
			return keychainData
		}

		// Fall back to file storage (for migration from old installations)
		const fileData = await this.fileStorage.getTokenData()
		if (fileData) {
			// Migrate token data to keychain if available
			if (await this.keychainStorage.isAvailable()) {
				try {
					await this.keychainStorage.setTokenData(fileData)
					await this.fileStorage.removeToken()
					if (getEnv('DEBUG')) {
						console.log('Migrated token data from file to keychain')
					}
				} catch {
					// Continue with file token if migration fails
				}
			}
			return fileData
		}

		return null
	}

	async setTokenData(data: StoredTokenData): Promise<void> {
		const storage = await this.getPreferredStorage()
		if (storage.setTokenData) {
			await storage.setTokenData(data)
		} else {
			// Fallback for storages that don't support tokenData
			await storage.setToken(data.accessToken)
		}
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
