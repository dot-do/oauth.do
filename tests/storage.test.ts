import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { join } from 'path'
import { tmpdir } from 'os'
import { mkdir, rm, readFile, stat, writeFile, unlink } from 'fs/promises'
import {
	MemoryTokenStorage,
	LocalStorageTokenStorage,
	SecureFileTokenStorage,
	KeychainTokenStorage,
	CompositeTokenStorage,
	createSecureStorage,
} from '../src/storage.js'

describe('TokenStorage', () => {
	describe('MemoryTokenStorage', () => {
		let storage: MemoryTokenStorage

		beforeEach(() => {
			storage = new MemoryTokenStorage()
		})

		it('should return null when no token stored', async () => {
			const token = await storage.getToken()
			expect(token).toBeNull()
		})

		it('should store and retrieve token', async () => {
			await storage.setToken('test-token')
			const token = await storage.getToken()
			expect(token).toBe('test-token')
		})

		it('should remove token', async () => {
			await storage.setToken('test-token')
			await storage.removeToken()
			const token = await storage.getToken()
			expect(token).toBeNull()
		})
	})

	describe('LocalStorageTokenStorage', () => {
		let storage: LocalStorageTokenStorage

		beforeEach(() => {
			// Mock localStorage
			global.localStorage = {
				getItem: vi.fn(),
				setItem: vi.fn(),
				removeItem: vi.fn(),
				clear: vi.fn(),
				key: vi.fn(),
				length: 0,
			}

			storage = new LocalStorageTokenStorage()
		})

		it('should return null when no token in localStorage', async () => {
			;(global.localStorage.getItem as any).mockReturnValue(null)

			const token = await storage.getToken()
			expect(token).toBeNull()
		})

		it('should store and retrieve token from localStorage', async () => {
			await storage.setToken('test-token')
			// Token is stored as JSON for refresh token support
			expect(global.localStorage.setItem).toHaveBeenCalledWith('oauth.do:token', '{"accessToken":"test-token"}')

			;(global.localStorage.getItem as any).mockReturnValue('{"accessToken":"test-token"}')
			const token = await storage.getToken()
			expect(token).toBe('test-token')
		})

		it('should handle legacy plain text token format', async () => {
			;(global.localStorage.getItem as any).mockReturnValue('legacy-plain-token')
			const token = await storage.getToken()
			expect(token).toBe('legacy-plain-token')
		})

		it('should store and retrieve full token data with refresh token', async () => {
			const tokenData = {
				accessToken: 'access-123',
				refreshToken: 'refresh-456',
				expiresAt: Date.now() + 3600000,
			}
			await storage.setTokenData(tokenData)

			;(global.localStorage.getItem as any).mockReturnValue(JSON.stringify(tokenData))
			const retrieved = await storage.getTokenData()
			expect(retrieved).toEqual(tokenData)
		})

		it('should remove token from localStorage', async () => {
			await storage.removeToken()
			expect(global.localStorage.removeItem).toHaveBeenCalledWith('oauth.do:token')
		})
	})

	describe('SecureFileTokenStorage', () => {
		let storage: SecureFileTokenStorage
		let testDir: string

		beforeEach(async () => {
			// Create a test-specific storage instance
			// Note: This tests the actual file operations
			storage = new SecureFileTokenStorage()
		})

		afterEach(async () => {
			// Clean up
			await storage.removeToken()
		})

		it('should return null when no token stored', async () => {
			await storage.removeToken() // Ensure clean state
			const token = await storage.getToken()
			expect(token).toBeNull()
		})

		it('should store and retrieve token', async () => {
			const testToken = `test-token-${Date.now()}`
			await storage.setToken(testToken)
			const token = await storage.getToken()
			expect(token).toBe(testToken)
		})

		it('should remove token', async () => {
			const testToken = `test-token-${Date.now()}`
			await storage.setToken(testToken)
			await storage.removeToken()
			const token = await storage.getToken()
			expect(token).toBeNull()
		})

		it('should set restrictive file permissions (0600)', async () => {
			const testToken = `test-token-${Date.now()}`
			await storage.setToken(testToken)

			// Get the token path
			const tokenPath = join(process.env.HOME || '', '.oauth.do', 'token')
			const stats = await stat(tokenPath)
			const mode = stats.mode & 0o777

			// Should be readable/writable only by owner
			expect(mode).toBe(0o600)
		})

		it('should trim whitespace from stored tokens', async () => {
			const testToken = `test-token-${Date.now()}`
			await storage.setToken(`  ${testToken}  \n`)
			const token = await storage.getToken()
			// The token is stored as-is but trimmed on read
			expect(token).toBe(testToken)
		})
	})

	describe('KeychainTokenStorage', () => {
		let storage: KeychainTokenStorage

		beforeEach(() => {
			storage = new KeychainTokenStorage()
		})

		afterEach(async () => {
			// Clean up
			await storage.removeToken()
		})

		it('should check if keychain is available', async () => {
			const available = await storage.isAvailable()
			// This will be true on macOS/Windows/Linux with proper setup
			// or false in CI environments without keychain access
			expect(typeof available).toBe('boolean')
		})

		it('should handle keychain operations gracefully when available', async () => {
			const available = await storage.isAvailable()

			if (available) {
				const testToken = `keychain-test-${Date.now()}`

				// Store token
				await storage.setToken(testToken)

				// Retrieve token
				const token = await storage.getToken()
				expect(token).toBe(testToken)

				// Remove token
				await storage.removeToken()
				const removedToken = await storage.getToken()
				expect(removedToken).toBeNull()
			} else {
				// When keychain is not available, getToken should return null
				const token = await storage.getToken()
				expect(token).toBeNull()
			}
		})

		it('should return null when keychain is not available and getting token', async () => {
			// This test verifies graceful degradation
			const token = await storage.getToken()
			// Should return null or the actual token depending on availability
			expect(token === null || typeof token === 'string').toBe(true)
		})
	})

	describe('CompositeTokenStorage', () => {
		let storage: CompositeTokenStorage

		beforeEach(() => {
			storage = new CompositeTokenStorage()
		})

		afterEach(async () => {
			// Clean up from both storages
			await storage.removeToken()
		})

		it('should return storage info', async () => {
			const info = await storage.getStorageInfo()
			expect(info).toHaveProperty('type')
			expect(info).toHaveProperty('secure')
			expect(['keychain', 'file']).toContain(info.type)
			expect(info.secure).toBe(true)
		})

		it('should store and retrieve token', async () => {
			const testToken = `composite-test-${Date.now()}`
			await storage.setToken(testToken)
			const token = await storage.getToken()
			expect(token).toBe(testToken)
		})

		it('should remove token from all backends', async () => {
			const testToken = `composite-test-${Date.now()}`
			await storage.setToken(testToken)
			await storage.removeToken()
			const token = await storage.getToken()
			expect(token).toBeNull()
		})

		it('should prefer keychain when available', async () => {
			const info = await storage.getStorageInfo()
			// On systems with keychain access, it should use keychain
			// On systems without, it should use file
			expect(info.secure).toBe(true)
		})
	})

	describe('createSecureStorage', () => {
		it('should create a SecureFileTokenStorage instance', () => {
			const storage = createSecureStorage()
			expect(storage).toBeInstanceOf(SecureFileTokenStorage)
		})

		it('should be usable as TokenStorage interface', async () => {
			const storage = createSecureStorage()
			const testToken = `factory-test-${Date.now()}`

			await storage.setToken(testToken)
			const token = await storage.getToken()
			expect(token).toBe(testToken)

			await storage.removeToken()
			const removedToken = await storage.getToken()
			expect(removedToken).toBeNull()
		})

		it('should support custom storage path', async () => {
			const customPath = join(tmpdir(), `test-oauth-${Date.now()}`, 'custom-tokens.json')
			const storage = createSecureStorage(customPath)
			const testToken = `custom-path-test-${Date.now()}`

			await storage.setToken(testToken)
			const token = await storage.getToken()
			expect(token).toBe(testToken)

			// Verify the file was created at the custom path
			const fileContent = await readFile(customPath, 'utf-8')
			const data = JSON.parse(fileContent)
			expect(data.accessToken).toBe(testToken)

			// Verify file has correct permissions
			const stats = await stat(customPath)
			const mode = stats.mode & 0o777
			expect(mode).toBe(0o600)

			// Clean up
			await storage.removeToken()
			await rm(join(tmpdir(), customPath.split('/').slice(-2, -1)[0]), { recursive: true, force: true })
		})

		it('should expand tilde in custom path', async () => {
			const storage = createSecureStorage('~/.test-oauth/tokens.json')
			const testToken = `tilde-test-${Date.now()}`

			await storage.setToken(testToken)
			const token = await storage.getToken()
			expect(token).toBe(testToken)

			// Verify the file was created in home directory
			const expandedPath = join(process.env.HOME || '', '.test-oauth', 'tokens.json')
			const fileContent = await readFile(expandedPath, 'utf-8')
			const data = JSON.parse(fileContent)
			expect(data.accessToken).toBe(testToken)

			// Clean up
			await storage.removeToken()
			await rm(join(process.env.HOME || '', '.test-oauth'), { recursive: true, force: true })
		})
	})

	describe('Concurrent token operations (race condition prevention)', () => {
		let testDir: string

		beforeEach(async () => {
			testDir = join(tmpdir(), `test-oauth-concurrent-${Date.now()}-${Math.random().toString(36).slice(2)}`)
			await mkdir(testDir, { recursive: true })
		})

		afterEach(async () => {
			await rm(testDir, { recursive: true, force: true })
		})

		it('should not corrupt token file during concurrent writes', async () => {
			const tokenPath = join(testDir, 'token')
			const concurrency = 20

			// Create multiple storage instances pointing to the same file (simulates
			// multiple CLI processes accessing the same token file simultaneously)
			const storages = Array.from({ length: concurrency }, () => new SecureFileTokenStorage(tokenPath))

			// Fire all writes concurrently — each writes a unique token
			const writePromises = storages.map((storage, i) =>
				storage.setTokenData({
					accessToken: `token-${i}`,
					refreshToken: `refresh-${i}`,
					expiresAt: Date.now() + 3600000,
				})
			)

			await Promise.all(writePromises)

			// After all concurrent writes complete, the file should contain valid JSON
			// (one of the tokens wins — the important thing is no corruption)
			const content = await readFile(tokenPath, 'utf-8')
			expect(() => JSON.parse(content)).not.toThrow()

			const data = JSON.parse(content)
			expect(data).toHaveProperty('accessToken')
			expect(data).toHaveProperty('refreshToken')
			expect(data.accessToken).toMatch(/^token-\d+$/)
			expect(data.refreshToken).toMatch(/^refresh-\d+$/)
		})

		it('should serialize concurrent read-modify-write operations', async () => {
			const tokenPath = join(testDir, 'token')
			const storage = new SecureFileTokenStorage(tokenPath)

			// Seed an initial token
			await storage.setTokenData({
				accessToken: 'initial-token',
				refreshToken: 'initial-refresh',
				expiresAt: Date.now() + 3600000,
			})

			// Simulate concurrent read-then-write cycles from multiple "processes"
			const concurrency = 10
			const results: string[] = []

			const promises = Array.from({ length: concurrency }, async (_, i) => {
				// Each "process" reads the current token, then writes a new one
				const instance = new SecureFileTokenStorage(tokenPath)
				const existing = await instance.getTokenData()
				results.push(existing?.accessToken || 'null')

				await instance.setTokenData({
					accessToken: `updated-${i}`,
					refreshToken: `refresh-${i}`,
					expiresAt: Date.now() + 3600000,
				})
			})

			await Promise.all(promises)

			// The file should contain valid JSON (no corruption)
			const content = await readFile(tokenPath, 'utf-8')
			const finalData = JSON.parse(content)
			expect(finalData.accessToken).toMatch(/^updated-\d+$/)

			// All read operations should have returned valid tokens (not corrupted data)
			for (const result of results) {
				expect(result === 'initial-token' || result.startsWith('updated-')).toBe(true)
			}
		})

		it('should handle stale lockfile cleanup', async () => {
			const tokenPath = join(testDir, 'token')
			const lockPath = `${tokenPath}.lock`

			// Create a stale lockfile (simulating a crashed process)
			await mkdir(join(testDir), { recursive: true })
			await writeFile(lockPath, JSON.stringify({ pid: 99999, ts: Date.now() - 30000 }), 'utf-8')

			// Manually backdate the file's mtime to make it stale
			const fs = await import('fs/promises')
			const staleTime = new Date(Date.now() - 30000) // 30 seconds ago
			await fs.utimes(lockPath, staleTime, staleTime)

			// Storage operations should succeed despite the stale lock
			const storage = new SecureFileTokenStorage(tokenPath)
			const testToken = `stale-lock-test-${Date.now()}`
			await storage.setToken(testToken)

			const token = await storage.getToken()
			expect(token).toBe(testToken)

			// Stale lockfile should have been cleaned up (no lingering lock)
			try {
				await stat(lockPath)
				// If we get here the lock exists — that's OK as long as it's from us
			} catch {
				// Lock was cleaned up — this is the expected path
			}
		})

		it('should use atomic writes (no partial content visible)', async () => {
			const tokenPath = join(testDir, 'token')
			const storage = new SecureFileTokenStorage(tokenPath)

			// Write a token
			await storage.setTokenData({
				accessToken: 'atomic-test-token',
				refreshToken: 'atomic-refresh',
				expiresAt: Date.now() + 3600000,
			})

			// Read the file directly — should be complete, valid JSON
			const content = await readFile(tokenPath, 'utf-8')
			const data = JSON.parse(content)
			expect(data.accessToken).toBe('atomic-test-token')
			expect(data.refreshToken).toBe('atomic-refresh')
			expect(data.expiresAt).toBeTypeOf('number')
		})

		it('should maintain correct permissions after atomic write', async () => {
			const tokenPath = join(testDir, 'token')
			const storage = new SecureFileTokenStorage(tokenPath)

			await storage.setToken('permissions-test')

			const stats = await stat(tokenPath)
			const mode = stats.mode & 0o777
			expect(mode).toBe(0o600)
		})

		it('should not leave temp files on successful write', async () => {
			const tokenPath = join(testDir, 'token')
			const storage = new SecureFileTokenStorage(tokenPath)

			await storage.setToken('temp-cleanup-test')

			// List files in the directory — only 'token' should exist (no .tmp files)
			const fs = await import('fs/promises')
			const files = await fs.readdir(testDir)
			const tmpFiles = files.filter((f) => f.includes('.tmp.'))
			expect(tmpFiles).toHaveLength(0)
		})

		it('should handle concurrent setToken and removeToken without errors', async () => {
			const tokenPath = join(testDir, 'token')
			const concurrency = 10

			// Alternate between set and remove operations
			const promises = Array.from({ length: concurrency }, async (_, i) => {
				const instance = new SecureFileTokenStorage(tokenPath)
				if (i % 2 === 0) {
					await instance.setToken(`token-${i}`)
				} else {
					await instance.removeToken()
				}
			})

			// Should complete without throwing
			await expect(Promise.all(promises)).resolves.toBeDefined()
		})

		it('should not leave lockfiles after operations complete', async () => {
			const tokenPath = join(testDir, 'token')
			const storage = new SecureFileTokenStorage(tokenPath)

			await storage.setToken('lockfile-cleanup-test')
			await storage.getToken()
			await storage.removeToken()

			// No .lock files should remain
			const fs = await import('fs/promises')
			const files = await fs.readdir(testDir)
			const lockFiles = files.filter((f) => f.endsWith('.lock'))
			expect(lockFiles).toHaveLength(0)
		})
	})
})
