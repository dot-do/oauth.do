import { describe, it, expect, beforeEach, afterEach, vi, type Mock } from 'vitest'

// Mock the external modules before importing cli
vi.mock('open', () => ({
	default: vi.fn().mockResolvedValue(undefined),
}))

vi.mock('../src/device.js', () => ({
	authorizeDevice: vi.fn(),
	pollForTokens: vi.fn(),
}))

vi.mock('../src/auth.js', () => ({
	getUser: vi.fn(),
	logout: vi.fn(),
}))

vi.mock('../src/storage.js', () => {
	const mockStorage = {
		getToken: vi.fn(),
		setToken: vi.fn(),
		setTokenData: vi.fn(),
		getTokenData: vi.fn(),
		removeToken: vi.fn(),
		getStorageInfo: vi.fn().mockResolvedValue({ type: 'file', secure: true, path: '~/.oauth.do/token' }),
	}
	return {
		createSecureStorage: vi.fn(() => mockStorage),
		SecureFileTokenStorage: vi.fn(() => mockStorage),
		__mockStorage: mockStorage,
	}
})

vi.mock('../src/config.js', () => ({
	configure: vi.fn(),
	getConfig: vi.fn().mockReturnValue({
		apiUrl: 'https://id.org.ai',
		clientId: 'test-client-id',
		authKitDomain: 'login.oauth.do',
		fetch: globalThis.fetch,
	}),
}))

// Import the mocked modules
import { authorizeDevice, pollForTokens } from '../src/device.js'
import { getUser, logout } from '../src/auth.js'
import { createSecureStorage, __mockStorage } from '../src/storage.js'
import { configure } from '../src/config.js'
import open from 'open'

// Get the mock storage instance
const mockStorage = __mockStorage as {
	getToken: Mock
	setToken: Mock
	setTokenData: Mock
	getTokenData: Mock
	removeToken: Mock
	getStorageInfo: Mock
}

describe('CLI', () => {
	// Store original process.argv and process.exit
	let originalArgv: string[]
	let originalExit: typeof process.exit
	let originalEnv: NodeJS.ProcessEnv

	// Capture console output
	let consoleLogSpy: Mock
	let consoleErrorSpy: Mock
	let consoleWarnSpy: Mock

	beforeEach(() => {
		vi.clearAllMocks()

		// Save originals
		originalArgv = process.argv
		originalExit = process.exit
		originalEnv = { ...process.env }

		// Mock process.exit
		process.exit = vi.fn() as unknown as typeof process.exit

		// Mock console methods
		consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
		consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
		consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

		// Reset mock storage default behavior
		mockStorage.getToken.mockResolvedValue(null)
		mockStorage.setToken.mockResolvedValue(undefined)
		mockStorage.setTokenData.mockResolvedValue(undefined)
		mockStorage.getTokenData.mockResolvedValue(null)
		mockStorage.removeToken.mockResolvedValue(undefined)
	})

	afterEach(() => {
		// Restore originals
		process.argv = originalArgv
		process.exit = originalExit
		process.env = originalEnv

		// Restore console
		consoleLogSpy.mockRestore()
		consoleErrorSpy.mockRestore()
		consoleWarnSpy.mockRestore()
	})

	/**
	 * Helper to run the CLI main function with specific args
	 */
	async function runCli(args: string[] = []) {
		process.argv = ['node', 'oauth.do', ...args]

		// We need to re-import main each time since it reads process.argv at import time
		// Clear the module cache to get a fresh import
		vi.resetModules()

		// Re-mock the modules
		vi.doMock('open', () => ({
			default: open,
		}))

		vi.doMock('../src/device.js', () => ({
			authorizeDevice,
			pollForTokens,
		}))

		vi.doMock('../src/auth.js', () => ({
			getUser,
			logout,
		}))

		vi.doMock('../src/storage.js', () => ({
			createSecureStorage: () => mockStorage,
			SecureFileTokenStorage: vi.fn(() => mockStorage),
		}))

		vi.doMock('../src/config.js', () => ({
			configure,
			getConfig: vi.fn().mockReturnValue({
				apiUrl: 'https://id.org.ai',
				clientId: 'test-client-id',
				authKitDomain: 'login.oauth.do',
				fetch: globalThis.fetch,
			}),
		}))

		const { main } = await import('../src/cli.js')
		await main()
	}

	describe('Command parsing (lines 366-416)', () => {
		describe('help flag handling', () => {
			it('should display help with --help flag', async () => {
				await runCli(['--help'])

				expect(consoleLogSpy).toHaveBeenCalled()
				const output = consoleLogSpy.mock.calls.map(call => call[0]).join('\n')
				expect(output).toContain('OAuth.do CLI')
				expect(output).toContain('Usage:')
				expect(output).toContain('Commands:')
				expect(output).toContain('login')
				expect(output).toContain('logout')
				expect(output).toContain('whoami')
				expect(output).toContain('token')
				expect(output).toContain('status')
				expect(process.exit).toHaveBeenCalledWith(0)
			})

			it('should display help with -h flag', async () => {
				await runCli(['-h'])

				expect(consoleLogSpy).toHaveBeenCalled()
				const output = consoleLogSpy.mock.calls.map(call => call[0]).join('\n')
				expect(output).toContain('OAuth.do CLI')
				expect(process.exit).toHaveBeenCalledWith(0)
			})
		})

		describe('version flag handling', () => {
			it('should display version with --version flag', async () => {
				await runCli(['--version'])

				// The version is loaded asynchronously via dynamic import
				// process.exit should be called with 0
				expect(process.exit).toHaveBeenCalledWith(0)
			})

			it('should display version with -v flag', async () => {
				await runCli(['-v'])

				expect(process.exit).toHaveBeenCalledWith(0)
			})
		})

		describe('debug flag handling', () => {
			it('should set DEBUG env when --debug flag is passed', async () => {
				// Mock getUser to return a valid user so autoLoginOrShowUser doesn't trigger login
				;(getUser as Mock).mockResolvedValue({
					user: { id: 'user-123', email: 'test@example.com', name: 'Test User' },
				})
				mockStorage.getToken.mockResolvedValue('test-token')

				await runCli(['--debug'])

				expect(process.env.DEBUG).toBe('true')
			})
		})

		describe('unknown command handling', () => {
			it('should display error for unknown command', async () => {
				await runCli(['invalid-command'])

				expect(consoleErrorSpy).toHaveBeenCalled()
				const errorOutput = consoleErrorSpy.mock.calls.map(call => call[0]).join('\n')
				expect(errorOutput).toContain('Error:')
				expect(errorOutput).toContain('Unknown command: invalid-command')
				expect(process.exit).toHaveBeenCalledWith(1)
			})

			it('should suggest running help for unknown command', async () => {
				await runCli(['foobar'])

				expect(consoleLogSpy).toHaveBeenCalled()
				const output = consoleLogSpy.mock.calls.map(call => call[0]).join('\n')
				expect(output).toContain('--help')
			})
		})

		describe('command argument parsing', () => {
			it('should correctly parse login command', async () => {
				const mockAuthResponse = {
					device_code: 'device-123',
					user_code: 'ABCD-1234',
					verification_uri: 'https://login.oauth.do/activate',
					verification_uri_complete: 'https://login.oauth.do/activate?user_code=ABCD-1234',
					expires_in: 600,
					interval: 5,
				}

				const mockTokenResponse = {
					access_token: 'access-token-123',
					token_type: 'Bearer',
					expires_in: 3600,
				}

				;(authorizeDevice as Mock).mockResolvedValue(mockAuthResponse)
				;(pollForTokens as Mock).mockResolvedValue(mockTokenResponse)
				;(getUser as Mock).mockResolvedValue({
					user: { id: 'user-123', email: 'test@example.com' },
				})
				;(open as unknown as Mock).mockResolvedValue(undefined)

				await runCli(['login'])

				expect(authorizeDevice).toHaveBeenCalled()
			})

			it('should correctly parse logout command', async () => {
				mockStorage.getToken.mockResolvedValue('existing-token')
				;(logout as Mock).mockResolvedValue(undefined)

				await runCli(['logout'])

				expect(mockStorage.getToken).toHaveBeenCalled()
			})

			it('should correctly parse whoami command', async () => {
				mockStorage.getToken.mockResolvedValue('existing-token')
				;(getUser as Mock).mockResolvedValue({
					user: { id: 'user-123', email: 'test@example.com', name: 'Test User' },
				})

				await runCli(['whoami'])

				expect(getUser).toHaveBeenCalledWith('existing-token')
			})

			it('should correctly parse token command', async () => {
				mockStorage.getToken.mockResolvedValue('my-secret-token')

				await runCli(['token'])

				expect(mockStorage.getToken).toHaveBeenCalled()
			})

			it('should correctly parse status command', async () => {
				mockStorage.getToken.mockResolvedValue('existing-token')
				;(getUser as Mock).mockResolvedValue({
					user: { id: 'user-123', email: 'test@example.com' },
				})

				await runCli(['status'])

				expect(mockStorage.getToken).toHaveBeenCalled()
			})

			it('should ignore flags when finding command', async () => {
				mockStorage.getToken.mockResolvedValue('existing-token')
				;(getUser as Mock).mockResolvedValue({
					user: { id: 'user-123', email: 'test@example.com', name: 'Test User' },
				})

				await runCli(['--debug', 'whoami'])

				expect(getUser).toHaveBeenCalledWith('existing-token')
			})
		})

		describe('default command (no arguments)', () => {
			it('should trigger autoLoginOrShowUser when no command is given', async () => {
				mockStorage.getToken.mockResolvedValue('existing-token')
				;(getUser as Mock).mockResolvedValue({
					user: { id: 'user-123', email: 'test@example.com', name: 'Test User' },
				})

				await runCli([])

				// Should check for existing token and show user info
				expect(mockStorage.getToken).toHaveBeenCalled()
				expect(getUser).toHaveBeenCalled()
			})
		})
	})

	describe('loginCommand (lines 133-196)', () => {
		const mockAuthResponse = {
			device_code: 'device-code-123',
			user_code: 'WXYZ-5678',
			verification_uri: 'https://login.oauth.do/activate',
			verification_uri_complete: 'https://login.oauth.do/activate?user_code=WXYZ-5678',
			expires_in: 600,
			interval: 5,
		}

		const mockTokenResponse = {
			access_token: 'access-token-xyz',
			token_type: 'Bearer',
			expires_in: 3600,
			refresh_token: 'refresh-token-xyz',
		}

		it('should complete successful login flow', async () => {
			;(authorizeDevice as Mock).mockResolvedValue(mockAuthResponse)
			;(pollForTokens as Mock).mockResolvedValue(mockTokenResponse)
			;(getUser as Mock).mockResolvedValue({
				user: { id: 'user-123', email: 'test@example.com', name: 'Test User' },
			})
			;(open as unknown as Mock).mockResolvedValue(undefined)

			await runCli(['login'])

			// Verify device authorization was called
			expect(authorizeDevice).toHaveBeenCalled()

			// Verify polling was called with correct params
			expect(pollForTokens).toHaveBeenCalledWith(
				mockAuthResponse.device_code,
				mockAuthResponse.interval,
				mockAuthResponse.expires_in
			)

			// Verify token was saved with full data (including refresh token)
			expect(mockStorage.setTokenData).toHaveBeenCalledWith({
				accessToken: mockTokenResponse.access_token,
				refreshToken: mockTokenResponse.refresh_token,
				expiresAt: expect.any(Number),
			})

			// Verify user info was fetched
			expect(getUser).toHaveBeenCalledWith(mockTokenResponse.access_token)

			// Verify success message was logged
			const output = consoleLogSpy.mock.calls.map(call => call[0]).join('\n')
			expect(output).toContain('Login successful')
		})

		it('should display device code instructions', async () => {
			;(authorizeDevice as Mock).mockResolvedValue(mockAuthResponse)
			;(pollForTokens as Mock).mockResolvedValue(mockTokenResponse)
			;(getUser as Mock).mockResolvedValue({
				user: { id: 'user-123', email: 'test@example.com' },
			})
			;(open as unknown as Mock).mockResolvedValue(undefined)

			await runCli(['login'])

			const output = consoleLogSpy.mock.calls.map(call => call[0]).join('\n')
			expect(output).toContain('To complete login')
			expect(output).toContain(mockAuthResponse.verification_uri)
			expect(output).toContain(mockAuthResponse.user_code)
			expect(output).toContain(mockAuthResponse.verification_uri_complete)
		})

		it('should attempt to open browser', async () => {
			;(authorizeDevice as Mock).mockResolvedValue(mockAuthResponse)
			;(pollForTokens as Mock).mockResolvedValue(mockTokenResponse)
			;(getUser as Mock).mockResolvedValue({
				user: { id: 'user-123', email: 'test@example.com' },
			})
			;(open as unknown as Mock).mockResolvedValue(undefined)

			await runCli(['login'])

			expect(open).toHaveBeenCalledWith(mockAuthResponse.verification_uri_complete)
		})

		it('should handle browser open failure gracefully', async () => {
			;(authorizeDevice as Mock).mockResolvedValue(mockAuthResponse)
			;(pollForTokens as Mock).mockResolvedValue(mockTokenResponse)
			;(getUser as Mock).mockResolvedValue({
				user: { id: 'user-123', email: 'test@example.com' },
			})
			;(open as unknown as Mock).mockRejectedValue(new Error('Browser not available'))

			await runCli(['login'])

			// Should still complete login successfully
			expect(mockStorage.setTokenData).toHaveBeenCalledWith({
				accessToken: mockTokenResponse.access_token,
				refreshToken: mockTokenResponse.refresh_token,
				expiresAt: expect.any(Number),
			})

			// Should show manual instructions
			const output = consoleLogSpy.mock.calls.map(call => call[0]).join('\n')
			expect(output).toContain('visit the URL')
		})

		it('should display user info after successful login', async () => {
			;(authorizeDevice as Mock).mockResolvedValue(mockAuthResponse)
			;(pollForTokens as Mock).mockResolvedValue(mockTokenResponse)
			;(getUser as Mock).mockResolvedValue({
				user: { id: 'user-123', email: 'test@example.com', name: 'Test User' },
			})
			;(open as unknown as Mock).mockResolvedValue(undefined)

			await runCli(['login'])

			const output = consoleLogSpy.mock.calls.map(call => call[0]).join('\n')
			expect(output).toContain('Test User')
			expect(output).toContain('test@example.com')
		})

		it('should handle login failure and exit with code 1', async () => {
			;(authorizeDevice as Mock).mockRejectedValue(new Error('Network error'))

			await runCli(['login'])

			expect(consoleErrorSpy).toHaveBeenCalled()
			const errorOutput = consoleErrorSpy.mock.calls.map(call => call[0]).join('\n')
			expect(errorOutput).toContain('Error:')
			expect(errorOutput).toContain('Login failed')
			expect(process.exit).toHaveBeenCalledWith(1)
		})

		it('should handle token polling failure', async () => {
			;(authorizeDevice as Mock).mockResolvedValue(mockAuthResponse)
			;(pollForTokens as Mock).mockRejectedValue(new Error('Access denied by user'))
			;(open as unknown as Mock).mockResolvedValue(undefined)

			await runCli(['login'])

			expect(consoleErrorSpy).toHaveBeenCalled()
			expect(process.exit).toHaveBeenCalledWith(1)
		})

		it('should handle expired device code', async () => {
			;(authorizeDevice as Mock).mockResolvedValue(mockAuthResponse)
			;(pollForTokens as Mock).mockRejectedValue(new Error('Device code expired'))
			;(open as unknown as Mock).mockResolvedValue(undefined)

			await runCli(['login'])

			expect(consoleErrorSpy).toHaveBeenCalled()
			expect(process.exit).toHaveBeenCalledWith(1)
		})
	})

	describe('logoutCommand (lines 200-222)', () => {
		it('should successfully logout when logged in', async () => {
			mockStorage.getToken.mockResolvedValue('existing-token')
			;(logout as Mock).mockResolvedValue(undefined)

			await runCli(['logout'])

			// Verify token was retrieved
			expect(mockStorage.getToken).toHaveBeenCalled()

			// Verify logout endpoint was called
			expect(logout).toHaveBeenCalledWith('existing-token')

			// Verify token was removed
			expect(mockStorage.removeToken).toHaveBeenCalled()

			// Verify success message
			const output = consoleLogSpy.mock.calls.map(call => call[0]).join('\n')
			expect(output).toContain('Logged out successfully')
		})

		it('should handle logout when not logged in', async () => {
			mockStorage.getToken.mockResolvedValue(null)

			await runCli(['logout'])

			// Should not call logout endpoint
			expect(logout).not.toHaveBeenCalled()

			// Should not try to remove token
			expect(mockStorage.removeToken).not.toHaveBeenCalled()

			// Should show info message
			const output = consoleLogSpy.mock.calls.map(call => call[0]).join('\n')
			expect(output).toContain('Not logged in')
		})

		it('should handle logout endpoint failure', async () => {
			mockStorage.getToken.mockResolvedValue('existing-token')
			;(logout as Mock).mockRejectedValue(new Error('Network error'))

			await runCli(['logout'])

			expect(consoleErrorSpy).toHaveBeenCalled()
			const errorOutput = consoleErrorSpy.mock.calls.map(call => call[0]).join('\n')
			expect(errorOutput).toContain('Logout failed')
			expect(process.exit).toHaveBeenCalledWith(1)
		})
	})

	describe('whoamiCommand (lines 227-259)', () => {
		it('should display user info when logged in', async () => {
			mockStorage.getToken.mockResolvedValue('valid-token')
			;(getUser as Mock).mockResolvedValue({
				user: { id: 'user-456', email: 'john@example.com', name: 'John Doe' },
			})

			await runCli(['whoami'])

			expect(getUser).toHaveBeenCalledWith('valid-token')

			const output = consoleLogSpy.mock.calls.map(call => call[0]).join('\n')
			expect(output).toContain('Authenticated as')
			expect(output).toContain('John Doe')
			expect(output).toContain('john@example.com')
			expect(output).toContain('user-456')
		})

		it('should display partial user info', async () => {
			mockStorage.getToken.mockResolvedValue('valid-token')
			;(getUser as Mock).mockResolvedValue({
				user: { id: 'user-789', email: 'jane@example.com' }, // No name
			})

			await runCli(['whoami'])

			const output = consoleLogSpy.mock.calls.map(call => call[0]).join('\n')
			expect(output).toContain('jane@example.com')
			expect(output).toContain('user-789')
		})

		it('should handle not logged in (no token)', async () => {
			mockStorage.getToken.mockResolvedValue(null)

			await runCli(['whoami'])

			expect(getUser).not.toHaveBeenCalled()

			const output = consoleLogSpy.mock.calls.map(call => call[0]).join('\n')
			expect(output).toContain('Not logged in')
			expect(output).toContain('oauth.do login')
		})

		it('should handle token that is no longer valid', async () => {
			mockStorage.getToken.mockResolvedValue('expired-token')
			;(getUser as Mock).mockResolvedValue({ user: null })

			await runCli(['whoami'])

			const output = consoleLogSpy.mock.calls.map(call => call[0]).join('\n')
			expect(output).toContain('Not authenticated')
			expect(output).toContain('oauth.do login')
		})

		it('should handle getUser failure', async () => {
			mockStorage.getToken.mockResolvedValue('valid-token')
			;(getUser as Mock).mockRejectedValue(new Error('API error'))

			await runCli(['whoami'])

			expect(consoleErrorSpy).toHaveBeenCalled()
			const errorOutput = consoleErrorSpy.mock.calls.map(call => call[0]).join('\n')
			expect(errorOutput).toContain('Failed to get user info')
			expect(process.exit).toHaveBeenCalledWith(1)
		})
	})

	describe('tokenCommand (lines 264-279)', () => {
		it('should display token when logged in', async () => {
			const testToken = 'my-secret-access-token-12345'
			mockStorage.getToken.mockResolvedValue(testToken)

			await runCli(['token'])

			expect(mockStorage.getToken).toHaveBeenCalled()

			// The token should be printed directly
			expect(consoleLogSpy).toHaveBeenCalledWith(testToken)
		})

		it('should handle no token found', async () => {
			mockStorage.getToken.mockResolvedValue(null)

			await runCli(['token'])

			const output = consoleLogSpy.mock.calls.map(call => call[0]).join('\n')
			expect(output).toContain('No token found')
			expect(output).toContain('oauth.do login')
		})

		it('should handle storage error', async () => {
			mockStorage.getToken.mockRejectedValue(new Error('Storage corrupted'))

			await runCli(['token'])

			expect(consoleErrorSpy).toHaveBeenCalled()
			const errorOutput = consoleErrorSpy.mock.calls.map(call => call[0]).join('\n')
			expect(errorOutput).toContain('Failed to get token')
			expect(process.exit).toHaveBeenCalledWith(1)
		})
	})

	describe('statusCommand (lines 284-318)', () => {
		it('should display status with valid token and user', async () => {
			mockStorage.getToken.mockResolvedValue('valid-token')
			;(getUser as Mock).mockResolvedValue({
				user: { id: 'user-123', email: 'status@example.com' },
			})

			await runCli(['status'])

			const output = consoleLogSpy.mock.calls.map(call => call[0]).join('\n')
			expect(output).toContain('OAuth.do Status')
			expect(output).toContain('Storage')
			expect(output).toContain('Auth')
			expect(output).toContain('Authenticated')
			expect(output).toContain('status@example.com')
		})

		it('should display status when not logged in', async () => {
			mockStorage.getToken.mockResolvedValue(null)

			await runCli(['status'])

			const output = consoleLogSpy.mock.calls.map(call => call[0]).join('\n')
			expect(output).toContain('OAuth.do Status')
			expect(output).toContain('Not authenticated')
			expect(output).toContain('oauth.do login')
		})

		it('should display status with expired token', async () => {
			mockStorage.getToken.mockResolvedValue('expired-token')
			;(getUser as Mock).mockResolvedValue({ user: null })

			await runCli(['status'])

			const output = consoleLogSpy.mock.calls.map(call => call[0]).join('\n')
			expect(output).toContain('Token expired or invalid')
			expect(output).toContain('oauth.do login')
		})

		it('should handle status check failure', async () => {
			mockStorage.getToken.mockResolvedValue('valid-token')
			;(getUser as Mock).mockRejectedValue(new Error('Network error'))

			await runCli(['status'])

			expect(consoleErrorSpy).toHaveBeenCalled()
			const errorOutput = consoleErrorSpy.mock.calls.map(call => call[0]).join('\n')
			expect(errorOutput).toContain('Failed to get status')
			expect(process.exit).toHaveBeenCalledWith(1)
		})

		it('should show storage info', async () => {
			mockStorage.getToken.mockResolvedValue('valid-token')
			;(getUser as Mock).mockResolvedValue({
				user: { id: 'user-123', email: 'test@example.com' },
			})

			await runCli(['status'])

			const output = consoleLogSpy.mock.calls.map(call => call[0]).join('\n')
			expect(output).toContain('Storage')
		})
	})

	describe('autoLoginOrShowUser (lines 325-358)', () => {
		it('should show user info if already logged in with valid token', async () => {
			mockStorage.getToken.mockResolvedValue('valid-token')
			;(getUser as Mock).mockResolvedValue({
				user: { id: 'user-123', email: 'auto@example.com', name: 'Auto User' },
			})

			await runCli([])

			const output = consoleLogSpy.mock.calls.map(call => call[0]).join('\n')
			expect(output).toContain('Already authenticated')
			expect(output).toContain('Auto User')
			expect(output).toContain('auto@example.com')
		})

		it('should trigger login flow if token is expired', async () => {
			mockStorage.getToken.mockResolvedValue('expired-token')

			// First call returns no user (expired), then login flow succeeds
			;(getUser as Mock)
				.mockResolvedValueOnce({ user: null })
				.mockResolvedValueOnce({
					user: { id: 'user-123', email: 'new@example.com' },
				})

			const mockAuthResponse = {
				device_code: 'device-code-auto',
				user_code: 'AUTO-1234',
				verification_uri: 'https://login.oauth.do/activate',
				verification_uri_complete: 'https://login.oauth.do/activate?user_code=AUTO-1234',
				expires_in: 600,
				interval: 5,
			}

			;(authorizeDevice as Mock).mockResolvedValue(mockAuthResponse)
			;(pollForTokens as Mock).mockResolvedValue({
				access_token: 'new-token',
				token_type: 'Bearer',
			})
			;(open as unknown as Mock).mockResolvedValue(undefined)

			await runCli([])

			// Should show session expired message
			const output = consoleLogSpy.mock.calls.map(call => call[0]).join('\n')
			expect(output).toContain('expired')

			// Should trigger new login
			expect(authorizeDevice).toHaveBeenCalled()
		})

		it('should trigger login flow if no token exists', async () => {
			mockStorage.getToken.mockResolvedValue(null)

			const mockAuthResponse = {
				device_code: 'device-code-new',
				user_code: 'NEW-5678',
				verification_uri: 'https://login.oauth.do/activate',
				verification_uri_complete: 'https://login.oauth.do/activate?user_code=NEW-5678',
				expires_in: 600,
				interval: 5,
			}

			;(authorizeDevice as Mock).mockResolvedValue(mockAuthResponse)
			;(pollForTokens as Mock).mockResolvedValue({
				access_token: 'brand-new-token',
				token_type: 'Bearer',
			})
			;(getUser as Mock).mockResolvedValue({
				user: { id: 'user-new', email: 'new@example.com' },
			})
			;(open as unknown as Mock).mockResolvedValue(undefined)

			await runCli([])

			// Should trigger login
			expect(authorizeDevice).toHaveBeenCalled()
		})

		it('should handle auth check failure and trigger login', async () => {
			mockStorage.getToken.mockResolvedValue('some-token')

			// First getUser call throws error
			;(getUser as Mock)
				.mockRejectedValueOnce(new Error('Auth check failed'))
				.mockResolvedValueOnce({
					user: { id: 'user-123', email: 'retry@example.com' },
				})

			const mockAuthResponse = {
				device_code: 'device-code-retry',
				user_code: 'RETRY-9999',
				verification_uri: 'https://login.oauth.do/activate',
				verification_uri_complete: 'https://login.oauth.do/activate?user_code=RETRY-9999',
				expires_in: 600,
				interval: 5,
			}

			;(authorizeDevice as Mock).mockResolvedValue(mockAuthResponse)
			;(pollForTokens as Mock).mockResolvedValue({
				access_token: 'retry-token',
				token_type: 'Bearer',
			})
			;(open as unknown as Mock).mockResolvedValue(undefined)

			await runCli([])

			// Should fall back to login on error
			expect(authorizeDevice).toHaveBeenCalled()
		})
	})

	describe('Environment variable configuration', () => {
		it('should call configure with env vars', async () => {
			process.env.OAUTH_API_URL = 'https://custom-api.example.com'
			process.env.OAUTH_CLIENT_ID = 'custom-client-id'
			process.env.OAUTH_AUTHKIT_DOMAIN = 'custom.login.example.com'

			mockStorage.getToken.mockResolvedValue('token')
			;(getUser as Mock).mockResolvedValue({
				user: { id: 'user-123', email: 'test@example.com' },
			})

			await runCli(['whoami'])

			// configure should be called at startup
			expect(configure).toHaveBeenCalled()
		})
	})

	describe('Error handling', () => {
		it('should handle unexpected errors in main', async () => {
			// Force an unexpected error by making storage throw
			mockStorage.getToken.mockImplementation(() => {
				throw new Error('Unexpected crash')
			})

			// Note: The main function has a top-level catch that handles this
			await runCli(['token'])

			// Should show error and exit
			expect(consoleErrorSpy).toHaveBeenCalled()
			expect(process.exit).toHaveBeenCalledWith(1)
		})
	})

	describe('Color output formatting', () => {
		it('should include ANSI color codes in output', async () => {
			mockStorage.getToken.mockResolvedValue('valid-token')
			;(getUser as Mock).mockResolvedValue({
				user: { id: 'user-123', email: 'test@example.com', name: 'Test User' },
			})

			await runCli(['whoami'])

			// Check that some output contains ANSI escape codes
			const allOutput = consoleLogSpy.mock.calls.map(call => String(call[0])).join('')

			// ANSI codes start with \x1b[
			expect(allOutput).toMatch(/\x1b\[/)
		})
	})
})
