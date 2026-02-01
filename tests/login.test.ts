import { describe, it, expect, beforeEach, afterEach, vi, type Mock } from 'vitest'
import { configure, getConfig } from '../src/config.js'
import type { StoredTokenData, TokenResponse, DeviceAuthorizationResponse } from '../src/types.js'

// Mock modules before importing the module under test
vi.mock('../src/device.js', () => ({
	authorizeDevice: vi.fn(),
	pollForTokens: vi.fn(),
}))

vi.mock('../src/auth.js', () => ({
	refreshAccessToken: vi.fn(),
	getUser: vi.fn(),
}))

vi.mock('../src/storage.js', () => ({
	createSecureStorage: vi.fn(),
}))

// Mock 'open' module for browser launch
vi.mock('open', () => ({
	default: vi.fn(),
}))

// Now import the module under test and mocked modules
import { ensureLoggedIn, forceLogin, ensureLoggedOut, _resetLoginState, type LoginOptions } from '../src/login.js'
import { authorizeDevice, pollForTokens } from '../src/device.js'
import { refreshAccessToken, getUser } from '../src/auth.js'
import { createSecureStorage } from '../src/storage.js'

describe('Login Module', () => {
	const mockClientId = 'client_test_123'
	const mockAccessToken = 'access_token_abc'
	const mockRefreshToken = 'refresh_token_xyz'
	const mockNewAccessToken = 'new_access_token_def'

	let mockStorage: {
		getToken: Mock
		setToken: Mock
		removeToken: Mock
		getTokenData: Mock
		setTokenData: Mock
	}

	let originalConfig: ReturnType<typeof getConfig>

	// Helper to reset singleton state between tests
	function resetLoginModule() {
		// Force reimport to reset singleton promises
		vi.resetModules()
	}

	beforeEach(() => {
		vi.clearAllMocks()
		vi.useFakeTimers({ shouldAdvanceTime: true })
		_resetLoginState()
		originalConfig = { ...getConfig() }

		// Create fresh mock storage for each test
		mockStorage = {
			getToken: vi.fn().mockResolvedValue(null),
			setToken: vi.fn().mockResolvedValue(undefined),
			removeToken: vi.fn().mockResolvedValue(undefined),
			getTokenData: vi.fn().mockResolvedValue(null),
			setTokenData: vi.fn().mockResolvedValue(undefined),
		}

		// Configure with mock client ID and silence console output
		configure({ clientId: mockClientId })

		// Setup default mock for createSecureStorage
		vi.mocked(createSecureStorage).mockReturnValue(mockStorage)
	})

	afterEach(() => {
		vi.useRealTimers()
		configure(originalConfig)
	})

	describe('ensureLoggedIn()', () => {
		it('should return existing token if already logged in and not expired', async () => {
			const futureExpiry = Date.now() + 60 * 60 * 1000 // 1 hour from now
			const tokenData: StoredTokenData = {
				accessToken: mockAccessToken,
				refreshToken: mockRefreshToken,
				expiresAt: futureExpiry,
			}

			mockStorage.getTokenData.mockResolvedValue(tokenData)
			mockStorage.getToken.mockResolvedValue(mockAccessToken)

			const result = await ensureLoggedIn({ storage: mockStorage })

			expect(result).toEqual({
				token: mockAccessToken,
				isNewLogin: false,
			})
			// Should not trigger device flow
			expect(authorizeDevice).not.toHaveBeenCalled()
			expect(pollForTokens).not.toHaveBeenCalled()
		})

		it('should trigger login flow if not logged in', async () => {
			mockStorage.getTokenData.mockResolvedValue(null)
			mockStorage.getToken.mockResolvedValue(null)

			const mockDeviceResponse: DeviceAuthorizationResponse = {
				device_code: 'device_code_123',
				user_code: 'ABCD-1234',
				verification_uri: 'https://login.oauth.do/activate',
				verification_uri_complete: 'https://login.oauth.do/activate?user_code=ABCD-1234',
				expires_in: 600,
				interval: 5,
			}

			const mockTokenResponse: TokenResponse = {
				access_token: mockAccessToken,
				refresh_token: mockRefreshToken,
				token_type: 'Bearer',
				expires_in: 3600,
			}

			vi.mocked(authorizeDevice).mockResolvedValue(mockDeviceResponse)
			vi.mocked(pollForTokens).mockResolvedValue(mockTokenResponse)

			const mockPrint = vi.fn()
			const result = await ensureLoggedIn({
				storage: mockStorage,
				openBrowser: false,
				print: mockPrint,
			})

			expect(result).toEqual({
				token: mockAccessToken,
				isNewLogin: true,
			})
			expect(authorizeDevice).toHaveBeenCalled()
			expect(pollForTokens).toHaveBeenCalledWith(
				mockDeviceResponse.device_code,
				mockDeviceResponse.interval,
				mockDeviceResponse.expires_in
			)
			expect(mockPrint).toHaveBeenCalledWith(expect.stringContaining('Logging in'))
		})

		it('should store token after successful login', async () => {
			mockStorage.getTokenData.mockResolvedValue(null)
			mockStorage.getToken.mockResolvedValue(null)

			const mockDeviceResponse: DeviceAuthorizationResponse = {
				device_code: 'device_code_123',
				user_code: 'ABCD-1234',
				verification_uri: 'https://login.oauth.do/activate',
				verification_uri_complete: 'https://login.oauth.do/activate?user_code=ABCD-1234',
				expires_in: 600,
				interval: 5,
			}

			const mockTokenResponse: TokenResponse = {
				access_token: mockAccessToken,
				refresh_token: mockRefreshToken,
				token_type: 'Bearer',
				expires_in: 3600,
			}

			vi.mocked(authorizeDevice).mockResolvedValue(mockDeviceResponse)
			vi.mocked(pollForTokens).mockResolvedValue(mockTokenResponse)

			await ensureLoggedIn({
				storage: mockStorage,
				openBrowser: false,
				print: vi.fn(),
			})

			expect(mockStorage.setTokenData).toHaveBeenCalledWith(
				expect.objectContaining({
					accessToken: mockAccessToken,
					refreshToken: mockRefreshToken,
					expiresAt: expect.any(Number),
				})
			)
		})

		it('should refresh token if expired and refresh token is available', async () => {
			const pastExpiry = Date.now() - 60 * 1000 // 1 minute ago (expired)
			const tokenData: StoredTokenData = {
				accessToken: mockAccessToken,
				refreshToken: mockRefreshToken,
				expiresAt: pastExpiry,
			}

			mockStorage.getTokenData.mockResolvedValue(tokenData)
			mockStorage.getToken.mockResolvedValue(mockAccessToken)

			const mockRefreshResponse: TokenResponse = {
				access_token: mockNewAccessToken,
				refresh_token: 'new_refresh_token',
				token_type: 'Bearer',
				expires_in: 3600,
			}

			vi.mocked(refreshAccessToken).mockResolvedValue(mockRefreshResponse)

			const result = await ensureLoggedIn({ storage: mockStorage })

			expect(result).toEqual({
				token: mockNewAccessToken,
				isNewLogin: false,
			})
			expect(refreshAccessToken).toHaveBeenCalledWith(mockRefreshToken)
			expect(mockStorage.setTokenData).toHaveBeenCalledWith(
				expect.objectContaining({
					accessToken: mockNewAccessToken,
					refreshToken: 'new_refresh_token',
				})
			)
		})

		it('should trigger login flow if refresh fails', async () => {
			const pastExpiry = Date.now() - 60 * 1000 // expired
			const tokenData: StoredTokenData = {
				accessToken: mockAccessToken,
				refreshToken: mockRefreshToken,
				expiresAt: pastExpiry,
			}

			mockStorage.getTokenData.mockResolvedValue(tokenData)
			mockStorage.getToken.mockResolvedValue(mockAccessToken)

			vi.mocked(refreshAccessToken).mockRejectedValue(new Error('Refresh failed'))

			const mockDeviceResponse: DeviceAuthorizationResponse = {
				device_code: 'device_code_123',
				user_code: 'ABCD-1234',
				verification_uri: 'https://login.oauth.do/activate',
				verification_uri_complete: 'https://login.oauth.do/activate?user_code=ABCD-1234',
				expires_in: 600,
				interval: 5,
			}

			const mockTokenResponse: TokenResponse = {
				access_token: mockNewAccessToken,
				refresh_token: 'new_refresh_token',
				token_type: 'Bearer',
				expires_in: 3600,
			}

			vi.mocked(authorizeDevice).mockResolvedValue(mockDeviceResponse)
			vi.mocked(pollForTokens).mockResolvedValue(mockTokenResponse)

			const result = await ensureLoggedIn({
				storage: mockStorage,
				openBrowser: false,
				print: vi.fn(),
			})

			expect(result).toEqual({
				token: mockNewAccessToken,
				isNewLogin: true,
			})
			expect(authorizeDevice).toHaveBeenCalled()
		})

		it('should validate token with getUser if no expiration info and no refresh token', async () => {
			// Token without expiration info or refresh token
			const tokenData: StoredTokenData = {
				accessToken: mockAccessToken,
			}

			mockStorage.getTokenData.mockResolvedValue(tokenData)
			mockStorage.getToken.mockResolvedValue(mockAccessToken)

			vi.mocked(getUser).mockResolvedValue({
				user: { id: 'user_123', email: 'test@example.com' },
				token: mockAccessToken,
			})

			const result = await ensureLoggedIn({ storage: mockStorage })

			expect(result).toEqual({
				token: mockAccessToken,
				isNewLogin: false,
			})
			expect(getUser).toHaveBeenCalledWith(mockAccessToken)
		})

		it('should use setToken if setTokenData is not available', async () => {
			const storageWithoutTokenData = {
				getToken: vi.fn().mockResolvedValue(null),
				setToken: vi.fn().mockResolvedValue(undefined),
				removeToken: vi.fn().mockResolvedValue(undefined),
			}

			const mockDeviceResponse: DeviceAuthorizationResponse = {
				device_code: 'device_code_123',
				user_code: 'ABCD-1234',
				verification_uri: 'https://login.oauth.do/activate',
				verification_uri_complete: 'https://login.oauth.do/activate?user_code=ABCD-1234',
				expires_in: 600,
				interval: 5,
			}

			const mockTokenResponse: TokenResponse = {
				access_token: mockAccessToken,
				token_type: 'Bearer',
			}

			vi.mocked(authorizeDevice).mockResolvedValue(mockDeviceResponse)
			vi.mocked(pollForTokens).mockResolvedValue(mockTokenResponse)

			await ensureLoggedIn({
				storage: storageWithoutTokenData,
				openBrowser: false,
				print: vi.fn(),
			})

			expect(storageWithoutTokenData.setToken).toHaveBeenCalledWith(mockAccessToken)
		})

		it('should refresh token before expiry (5 minute buffer)', async () => {
			// Token that expires in 4 minutes (within 5-minute buffer)
			const nearExpiry = Date.now() + 4 * 60 * 1000
			const tokenData: StoredTokenData = {
				accessToken: mockAccessToken,
				refreshToken: mockRefreshToken,
				expiresAt: nearExpiry,
			}

			mockStorage.getTokenData.mockResolvedValue(tokenData)
			mockStorage.getToken.mockResolvedValue(mockAccessToken)

			const mockRefreshResponse: TokenResponse = {
				access_token: mockNewAccessToken,
				token_type: 'Bearer',
				expires_in: 3600,
			}

			vi.mocked(refreshAccessToken).mockResolvedValue(mockRefreshResponse)

			const result = await ensureLoggedIn({ storage: mockStorage })

			// Should have refreshed because token is within 5-minute buffer
			expect(refreshAccessToken).toHaveBeenCalledWith(mockRefreshToken)
			expect(result.token).toBe(mockNewAccessToken)
		})

		it('should include provider when specified', async () => {
			mockStorage.getTokenData.mockResolvedValue(null)
			mockStorage.getToken.mockResolvedValue(null)

			const mockDeviceResponse: DeviceAuthorizationResponse = {
				device_code: 'device_code_123',
				user_code: 'ABCD-1234',
				verification_uri: 'https://login.oauth.do/activate',
				verification_uri_complete: 'https://login.oauth.do/activate?user_code=ABCD-1234',
				expires_in: 600,
				interval: 5,
			}

			const mockTokenResponse: TokenResponse = {
				access_token: mockAccessToken,
				token_type: 'Bearer',
			}

			vi.mocked(authorizeDevice).mockResolvedValue(mockDeviceResponse)
			vi.mocked(pollForTokens).mockResolvedValue(mockTokenResponse)

			await ensureLoggedIn({
				storage: mockStorage,
				openBrowser: false,
				print: vi.fn(),
				provider: 'GitHubOAuth',
			})

			expect(authorizeDevice).toHaveBeenCalledWith({ provider: 'GitHubOAuth' })
		})
	})

	describe('forceLogin()', () => {
		it('should always trigger login flow even if token exists', async () => {
			const futureExpiry = Date.now() + 60 * 60 * 1000
			const tokenData: StoredTokenData = {
				accessToken: mockAccessToken,
				refreshToken: mockRefreshToken,
				expiresAt: futureExpiry,
			}

			// Set up existing token
			mockStorage.getTokenData.mockResolvedValue(tokenData)
			mockStorage.getToken.mockResolvedValue(mockAccessToken)

			const mockDeviceResponse: DeviceAuthorizationResponse = {
				device_code: 'device_code_123',
				user_code: 'ABCD-1234',
				verification_uri: 'https://login.oauth.do/activate',
				verification_uri_complete: 'https://login.oauth.do/activate?user_code=ABCD-1234',
				expires_in: 600,
				interval: 5,
			}

			const mockTokenResponse: TokenResponse = {
				access_token: mockNewAccessToken,
				token_type: 'Bearer',
				expires_in: 3600,
			}

			vi.mocked(authorizeDevice).mockResolvedValue(mockDeviceResponse)
			vi.mocked(pollForTokens).mockResolvedValue(mockTokenResponse)

			// After removeToken, getToken returns null for ensureLoggedIn's check
			mockStorage.removeToken.mockImplementation(async () => {
				mockStorage.getTokenData.mockResolvedValue(null)
				mockStorage.getToken.mockResolvedValue(null)
			})

			const result = await forceLogin({
				storage: mockStorage,
				openBrowser: false,
				print: vi.fn(),
			})

			expect(mockStorage.removeToken).toHaveBeenCalled()
			expect(authorizeDevice).toHaveBeenCalled()
			expect(result.token).toBe(mockNewAccessToken)
			expect(result.isNewLogin).toBe(true)
		})

		it('should return new token after forced login', async () => {
			mockStorage.getTokenData.mockResolvedValue(null)
			mockStorage.getToken.mockResolvedValue(null)

			const mockDeviceResponse: DeviceAuthorizationResponse = {
				device_code: 'device_code_123',
				user_code: 'EFGH-5678',
				verification_uri: 'https://login.oauth.do/activate',
				verification_uri_complete: 'https://login.oauth.do/activate?user_code=EFGH-5678',
				expires_in: 600,
				interval: 5,
			}

			const mockTokenResponse: TokenResponse = {
				access_token: 'forced_new_token',
				refresh_token: 'forced_refresh_token',
				token_type: 'Bearer',
				expires_in: 3600,
			}

			vi.mocked(authorizeDevice).mockResolvedValue(mockDeviceResponse)
			vi.mocked(pollForTokens).mockResolvedValue(mockTokenResponse)

			const result = await forceLogin({
				storage: mockStorage,
				openBrowser: false,
				print: vi.fn(),
			})

			expect(result).toEqual({
				token: 'forced_new_token',
				isNewLogin: true,
			})
		})
	})

	describe('ensureLoggedOut()', () => {
		it('should clear stored token', async () => {
			const mockPrint = vi.fn()

			await ensureLoggedOut({
				storage: mockStorage,
				print: mockPrint,
			})

			expect(mockStorage.removeToken).toHaveBeenCalled()
			expect(mockPrint).toHaveBeenCalledWith(expect.stringContaining('Logged out'))
		})

		it('should succeed even when no token existed', async () => {
			mockStorage.getToken.mockResolvedValue(null)

			const mockPrint = vi.fn()

			// Should not throw
			await ensureLoggedOut({
				storage: mockStorage,
				print: mockPrint,
			})

			expect(mockStorage.removeToken).toHaveBeenCalled()
			expect(mockPrint).toHaveBeenCalledWith(expect.stringContaining('Logged out'))
		})

		it('should use default storage if not provided', async () => {
			const mockPrint = vi.fn()

			await ensureLoggedOut({ print: mockPrint })

			expect(createSecureStorage).toHaveBeenCalled()
		})
	})

	describe('Token refresh logic', () => {
		it('should keep refresh token if new one is not provided', async () => {
			const pastExpiry = Date.now() - 60 * 1000
			const tokenData: StoredTokenData = {
				accessToken: mockAccessToken,
				refreshToken: mockRefreshToken,
				expiresAt: pastExpiry,
			}

			mockStorage.getTokenData.mockResolvedValue(tokenData)
			mockStorage.getToken.mockResolvedValue(mockAccessToken)

			// Response without new refresh token
			const mockRefreshResponse: TokenResponse = {
				access_token: mockNewAccessToken,
				token_type: 'Bearer',
				expires_in: 3600,
			}

			vi.mocked(refreshAccessToken).mockResolvedValue(mockRefreshResponse)

			await ensureLoggedIn({ storage: mockStorage })

			// Should keep old refresh token
			expect(mockStorage.setTokenData).toHaveBeenCalledWith(
				expect.objectContaining({
					accessToken: mockNewAccessToken,
					refreshToken: mockRefreshToken, // Original refresh token kept
				})
			)
		})

		it('should calculate expiration time from expires_in', async () => {
			mockStorage.getTokenData.mockResolvedValue(null)
			mockStorage.getToken.mockResolvedValue(null)

			const mockDeviceResponse: DeviceAuthorizationResponse = {
				device_code: 'device_code_123',
				user_code: 'ABCD-1234',
				verification_uri: 'https://login.oauth.do/activate',
				verification_uri_complete: 'https://login.oauth.do/activate?user_code=ABCD-1234',
				expires_in: 600,
				interval: 5,
			}

			const mockTokenResponse: TokenResponse = {
				access_token: mockAccessToken,
				token_type: 'Bearer',
				expires_in: 3600, // 1 hour
			}

			vi.mocked(authorizeDevice).mockResolvedValue(mockDeviceResponse)
			vi.mocked(pollForTokens).mockResolvedValue(mockTokenResponse)

			const beforeCall = Date.now()
			await ensureLoggedIn({
				storage: mockStorage,
				openBrowser: false,
				print: vi.fn(),
			})

			expect(mockStorage.setTokenData).toHaveBeenCalled()
			const savedData = mockStorage.setTokenData.mock.calls[0][0] as StoredTokenData
			expect(savedData.expiresAt).toBeDefined()
			// expiresAt should be approximately now + 3600 seconds
			expect(savedData.expiresAt! - beforeCall).toBeGreaterThanOrEqual(3600 * 1000 - 1000)
			expect(savedData.expiresAt! - beforeCall).toBeLessThanOrEqual(3600 * 1000 + 1000)
		})

		it('should handle undefined expires_in', async () => {
			mockStorage.getTokenData.mockResolvedValue(null)
			mockStorage.getToken.mockResolvedValue(null)

			const mockDeviceResponse: DeviceAuthorizationResponse = {
				device_code: 'device_code_123',
				user_code: 'ABCD-1234',
				verification_uri: 'https://login.oauth.do/activate',
				verification_uri_complete: 'https://login.oauth.do/activate?user_code=ABCD-1234',
				expires_in: 600,
				interval: 5,
			}

			const mockTokenResponse: TokenResponse = {
				access_token: mockAccessToken,
				token_type: 'Bearer',
				// No expires_in
			}

			vi.mocked(authorizeDevice).mockResolvedValue(mockDeviceResponse)
			vi.mocked(pollForTokens).mockResolvedValue(mockTokenResponse)

			await ensureLoggedIn({
				storage: mockStorage,
				openBrowser: false,
				print: vi.fn(),
			})

			expect(mockStorage.setTokenData).toHaveBeenCalled()
			const savedData = mockStorage.setTokenData.mock.calls[0][0] as StoredTokenData
			expect(savedData.expiresAt).toBeUndefined()
		})
	})

	describe('Singleton protection (concurrent login/refresh prevention)', () => {
		it('should prevent concurrent login attempts', async () => {
			// We need to reimport to test singleton behavior
			// Clear and re-setup mocks
			vi.doUnmock('../src/login.js')

			mockStorage.getTokenData.mockResolvedValue(null)
			mockStorage.getToken.mockResolvedValue(null)

			const mockDeviceResponse: DeviceAuthorizationResponse = {
				device_code: 'device_code_123',
				user_code: 'ABCD-1234',
				verification_uri: 'https://login.oauth.do/activate',
				verification_uri_complete: 'https://login.oauth.do/activate?user_code=ABCD-1234',
				expires_in: 600,
				interval: 5,
			}

			const mockTokenResponse: TokenResponse = {
				access_token: mockAccessToken,
				token_type: 'Bearer',
				expires_in: 3600,
			}

			// Add a delay to pollForTokens to simulate slow network
			let pollCalls = 0
			vi.mocked(authorizeDevice).mockResolvedValue(mockDeviceResponse)
			vi.mocked(pollForTokens).mockImplementation(async () => {
				pollCalls++
				await new Promise((resolve) => setTimeout(resolve, 100))
				return mockTokenResponse
			})

			const options: LoginOptions = {
				storage: mockStorage,
				openBrowser: false,
				print: vi.fn(),
			}

			// Start two concurrent login attempts
			const [result1, result2] = await Promise.all([ensureLoggedIn(options), ensureLoggedIn(options)])

			// Both should return the same token
			expect(result1.token).toBe(mockAccessToken)
			expect(result2.token).toBe(mockAccessToken)

			// pollForTokens should only have been called once due to singleton
			expect(pollCalls).toBe(1)
		})

		it('should prevent concurrent refresh attempts', async () => {
			const pastExpiry = Date.now() - 60 * 1000
			const tokenData: StoredTokenData = {
				accessToken: mockAccessToken,
				refreshToken: mockRefreshToken,
				expiresAt: pastExpiry,
			}

			mockStorage.getTokenData.mockResolvedValue(tokenData)
			mockStorage.getToken.mockResolvedValue(mockAccessToken)

			const mockRefreshResponse: TokenResponse = {
				access_token: mockNewAccessToken,
				token_type: 'Bearer',
				expires_in: 3600,
			}

			let refreshCalls = 0
			vi.mocked(refreshAccessToken).mockImplementation(async () => {
				refreshCalls++
				await new Promise((resolve) => setTimeout(resolve, 100))
				return mockRefreshResponse
			})

			const options: LoginOptions = { storage: mockStorage }

			// Start two concurrent refresh attempts
			const [result1, result2] = await Promise.all([ensureLoggedIn(options), ensureLoggedIn(options)])

			// Both should return the same refreshed token
			expect(result1.token).toBe(mockNewAccessToken)
			expect(result2.token).toBe(mockNewAccessToken)

			// refreshAccessToken should only have been called once due to singleton
			expect(refreshCalls).toBe(1)
		})
	})

	describe('Browser auto-launch', () => {
		it('should open browser when openBrowser is true', async () => {
			mockStorage.getTokenData.mockResolvedValue(null)
			mockStorage.getToken.mockResolvedValue(null)

			const mockDeviceResponse: DeviceAuthorizationResponse = {
				device_code: 'device_code_123',
				user_code: 'ABCD-1234',
				verification_uri: 'https://login.oauth.do/activate',
				verification_uri_complete: 'https://login.oauth.do/activate?user_code=ABCD-1234',
				expires_in: 600,
				interval: 5,
			}

			const mockTokenResponse: TokenResponse = {
				access_token: mockAccessToken,
				token_type: 'Bearer',
			}

			vi.mocked(authorizeDevice).mockResolvedValue(mockDeviceResponse)
			vi.mocked(pollForTokens).mockResolvedValue(mockTokenResponse)

			// Use the already-mocked import (don't dynamically import - that bypasses mock!)
			const open = await vi.importMock<typeof import('open')>('open')

			await ensureLoggedIn({
				storage: mockStorage,
				openBrowser: true,
				print: vi.fn(),
			})

			expect(open.default).toHaveBeenCalledWith(mockDeviceResponse.verification_uri_complete)
		})

		it('should not open browser when openBrowser is false', async () => {
			mockStorage.getTokenData.mockResolvedValue(null)
			mockStorage.getToken.mockResolvedValue(null)

			const mockDeviceResponse: DeviceAuthorizationResponse = {
				device_code: 'device_code_123',
				user_code: 'ABCD-1234',
				verification_uri: 'https://login.oauth.do/activate',
				verification_uri_complete: 'https://login.oauth.do/activate?user_code=ABCD-1234',
				expires_in: 600,
				interval: 5,
			}

			const mockTokenResponse: TokenResponse = {
				access_token: mockAccessToken,
				token_type: 'Bearer',
			}

			vi.mocked(authorizeDevice).mockResolvedValue(mockDeviceResponse)
			vi.mocked(pollForTokens).mockResolvedValue(mockTokenResponse)

			// Use the already-mocked import
			const open = await vi.importMock<typeof import('open')>('open')
			vi.mocked(open.default).mockClear()

			await ensureLoggedIn({
				storage: mockStorage,
				openBrowser: false,
				print: vi.fn(),
			})

			expect(open.default).not.toHaveBeenCalled()
		})
	})

	describe('Print output', () => {
		it('should use custom print function', async () => {
			mockStorage.getTokenData.mockResolvedValue(null)
			mockStorage.getToken.mockResolvedValue(null)

			const mockDeviceResponse: DeviceAuthorizationResponse = {
				device_code: 'device_code_123',
				user_code: 'TEST-CODE',
				verification_uri: 'https://login.oauth.do/activate',
				verification_uri_complete: 'https://login.oauth.do/activate?user_code=TEST-CODE',
				expires_in: 600,
				interval: 5,
			}

			const mockTokenResponse: TokenResponse = {
				access_token: mockAccessToken,
				token_type: 'Bearer',
			}

			vi.mocked(authorizeDevice).mockResolvedValue(mockDeviceResponse)
			vi.mocked(pollForTokens).mockResolvedValue(mockTokenResponse)

			const mockPrint = vi.fn()

			await ensureLoggedIn({
				storage: mockStorage,
				openBrowser: false,
				print: mockPrint,
			})

			// Should have printed login instructions
			expect(mockPrint).toHaveBeenCalledWith(expect.stringContaining('Logging in'))
			expect(mockPrint).toHaveBeenCalledWith(expect.stringContaining('TEST-CODE'))
			expect(mockPrint).toHaveBeenCalledWith(expect.stringContaining('Visit'))
			expect(mockPrint).toHaveBeenCalledWith(expect.stringContaining('Login successful'))
		})

		it('should use console.log as default print function', async () => {
			mockStorage.getTokenData.mockResolvedValue(null)
			mockStorage.getToken.mockResolvedValue(null)

			const mockDeviceResponse: DeviceAuthorizationResponse = {
				device_code: 'device_code_123',
				user_code: 'ABCD-1234',
				verification_uri: 'https://login.oauth.do/activate',
				verification_uri_complete: 'https://login.oauth.do/activate?user_code=ABCD-1234',
				expires_in: 600,
				interval: 5,
			}

			const mockTokenResponse: TokenResponse = {
				access_token: mockAccessToken,
				token_type: 'Bearer',
			}

			vi.mocked(authorizeDevice).mockResolvedValue(mockDeviceResponse)
			vi.mocked(pollForTokens).mockResolvedValue(mockTokenResponse)

			const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})

			await ensureLoggedIn({
				storage: mockStorage,
				openBrowser: false,
			})

			expect(consoleSpy).toHaveBeenCalled()
			consoleSpy.mockRestore()
		})
	})
})
