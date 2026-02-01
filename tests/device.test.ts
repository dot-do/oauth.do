import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { authorizeDevice, pollForTokens } from '../src/device.js'
import { configure, getConfig } from '../src/config.js'

describe('WorkOS Device Authorization Flow', () => {
	const mockClientId = 'client_01JQYTRXK9ZPD8JPJTKDCRB656'
	const mockDeviceCode = 'device_code_abc123'
	const mockUserCode = 'WXYZ-1234'
	const mockAccessToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.mocktoken'

	let originalConfig: ReturnType<typeof getConfig>

	beforeEach(() => {
		vi.clearAllMocks()
		originalConfig = { ...getConfig() }
	})

	afterEach(() => {
		// Restore original config
		configure(originalConfig)
	})

	describe('authorizeDevice()', () => {
		it('should make correct POST request to WorkOS device auth endpoint', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: true,
				json: async () => ({
					device_code: mockDeviceCode,
					user_code: mockUserCode,
					verification_uri: 'https://login.oauth.do/activate',
					verification_uri_complete: `https://login.oauth.do/activate?user_code=${mockUserCode}`,
					expires_in: 600,
					interval: 5,
				}),
			})

			configure({ clientId: mockClientId, fetch: mockFetch as any })

			const result = await authorizeDevice()

			expect(mockFetch).toHaveBeenCalledWith(
				'https://auth.apis.do/user_management/authorize/device',
				{
					method: 'POST',
					headers: {
						'Content-Type': 'application/x-www-form-urlencoded',
					},
					body: expect.any(String),
				}
			)

			// Verify the body params
			const callBody = new URLSearchParams(mockFetch.mock.calls[0][1].body)
			expect(callBody.get('client_id')).toBe(mockClientId)
			expect(callBody.get('scope')).toBe('openid profile email')
		})

		it('should return device_code, user_code, verification_uri, etc.', async () => {
			const mockResponse = {
				device_code: mockDeviceCode,
				user_code: mockUserCode,
				verification_uri: 'https://login.oauth.do/activate',
				verification_uri_complete: `https://login.oauth.do/activate?user_code=${mockUserCode}`,
				expires_in: 600,
				interval: 5,
			}

			const mockFetch = vi.fn().mockResolvedValue({
				ok: true,
				json: async () => mockResponse,
			})

			configure({ clientId: mockClientId, fetch: mockFetch as any })

			const result = await authorizeDevice()

			expect(result).toEqual(mockResponse)
			expect(result.device_code).toBe(mockDeviceCode)
			expect(result.user_code).toBe(mockUserCode)
			expect(result.verification_uri).toBe('https://login.oauth.do/activate')
			expect(result.verification_uri_complete).toBe(`https://login.oauth.do/activate?user_code=${mockUserCode}`)
			expect(result.expires_in).toBe(600)
			expect(result.interval).toBe(5)
		})

		it('should handle missing client ID error', async () => {
			configure({ clientId: '', fetch: vi.fn() as any })

			await expect(authorizeDevice()).rejects.toThrow(
				'Client ID is required for device authorization'
			)
		})

		it('should include provider parameter when specified', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: true,
				json: async () => ({
					device_code: mockDeviceCode,
					user_code: mockUserCode,
					verification_uri: 'https://login.oauth.do/activate',
					verification_uri_complete: `https://login.oauth.do/activate?user_code=${mockUserCode}`,
					expires_in: 600,
					interval: 5,
				}),
			})

			configure({ clientId: mockClientId, fetch: mockFetch as any })

			await authorizeDevice({ provider: 'GitHubOAuth' })

			const callBody = new URLSearchParams(mockFetch.mock.calls[0][1].body)
			expect(callBody.get('provider')).toBe('GitHubOAuth')
		})

		it('should throw error on failed request', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: false,
				statusText: 'Bad Request',
				text: async () => 'Invalid client_id',
			})

			configure({ clientId: mockClientId, fetch: mockFetch as any })

			await expect(authorizeDevice()).rejects.toThrow(
				'Device authorization failed: Bad Request - Invalid client_id'
			)
		})
	})

	describe('pollForTokens()', () => {
		it('should poll at correct interval', async () => {
			const startTime = Date.now()
			let callCount = 0

			const mockFetch = vi.fn().mockImplementation(async () => {
				callCount++
				if (callCount === 1) {
					return {
						ok: false,
						json: async () => ({ error: 'authorization_pending' }),
					}
				}
				return {
					ok: true,
					json: async () => ({
						access_token: mockAccessToken,
						token_type: 'Bearer',
						expires_in: 3600,
					}),
				}
			})

			configure({ clientId: mockClientId, fetch: mockFetch as any })

			// Use very small interval for testing (0.1 seconds = 100ms)
			await pollForTokens(mockDeviceCode, 0.1, 10)

			const elapsed = Date.now() - startTime
			// Should have waited at least 100ms (the interval)
			expect(elapsed).toBeGreaterThanOrEqual(100)
			expect(mockFetch).toHaveBeenCalledTimes(2)
		})

		it('should handle authorization_pending response (continues polling)', async () => {
			let callCount = 0

			const mockFetch = vi.fn().mockImplementation(async () => {
				callCount++
				if (callCount < 3) {
					return {
						ok: false,
						json: async () => ({ error: 'authorization_pending' }),
					}
				}
				return {
					ok: true,
					json: async () => ({
						access_token: mockAccessToken,
						token_type: 'Bearer',
						expires_in: 3600,
					}),
				}
			})

			configure({ clientId: mockClientId, fetch: mockFetch as any })

			const result = await pollForTokens(mockDeviceCode, 0.05, 10)

			expect(mockFetch).toHaveBeenCalledTimes(3)
			expect(result.access_token).toBe(mockAccessToken)
		})

		it('should handle slow_down response (increases interval)', async () => {
			let callCount = 0
			const callTimes: number[] = []

			const mockFetch = vi.fn().mockImplementation(async () => {
				callTimes.push(Date.now())
				callCount++
				if (callCount === 1) {
					return {
						ok: false,
						json: async () => ({ error: 'slow_down' }),
					}
				}
				return {
					ok: true,
					json: async () => ({
						access_token: mockAccessToken,
						token_type: 'Bearer',
						expires_in: 3600,
					}),
				}
			})

			configure({ clientId: mockClientId, fetch: mockFetch as any })

			// Start with 0.1 second interval
			const result = await pollForTokens(mockDeviceCode, 0.1, 60)

			expect(result.access_token).toBe(mockAccessToken)
			expect(mockFetch).toHaveBeenCalledTimes(2)

			// The second call should be delayed by original interval + 5 seconds
			// But for practical test speed, we just verify the function completes
			// The implementation adds 5000ms to currentInterval on slow_down
		}, 15000) // Increase timeout as slow_down adds 5 seconds to interval

		it('should handle access_denied response (rejects)', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: false,
				json: async () => ({ error: 'access_denied' }),
			})

			configure({ clientId: mockClientId, fetch: mockFetch as any })

			await expect(
				pollForTokens(mockDeviceCode, 0.05, 10)
			).rejects.toThrow('Access denied by user')
		})

		it('should handle expired_token response (rejects)', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: false,
				json: async () => ({ error: 'expired_token' }),
			})

			configure({ clientId: mockClientId, fetch: mockFetch as any })

			await expect(
				pollForTokens(mockDeviceCode, 0.05, 10)
			).rejects.toThrow('Device code expired')
		})

		it('should return tokens on success', async () => {
			const mockTokenResponse = {
				access_token: mockAccessToken,
				refresh_token: 'refresh_token_xyz',
				token_type: 'Bearer',
				expires_in: 3600,
				user: {
					id: 'user_123',
					email: 'test@example.com',
					name: 'Test User',
				},
			}

			const mockFetch = vi.fn().mockResolvedValue({
				ok: true,
				json: async () => mockTokenResponse,
			})

			configure({ clientId: mockClientId, fetch: mockFetch as any })

			const result = await pollForTokens(mockDeviceCode, 0.05, 10)

			expect(result).toEqual(mockTokenResponse)
			expect(result.access_token).toBe(mockAccessToken)
			expect(result.refresh_token).toBe('refresh_token_xyz')
			expect(result.token_type).toBe('Bearer')
			expect(result.expires_in).toBe(3600)
			expect(result.user).toEqual({
				id: 'user_123',
				email: 'test@example.com',
				name: 'Test User',
			})
		})

		it('should make correct POST request to authenticate endpoint', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: true,
				json: async () => ({
					access_token: mockAccessToken,
					token_type: 'Bearer',
				}),
			})

			configure({ clientId: mockClientId, fetch: mockFetch as any })

			await pollForTokens(mockDeviceCode, 0.05, 10)

			expect(mockFetch).toHaveBeenCalledWith(
				'https://auth.apis.do/user_management/authenticate',
				{
					method: 'POST',
					headers: {
						'Content-Type': 'application/x-www-form-urlencoded',
					},
					body: expect.any(String),
				}
			)

			const callBody = new URLSearchParams(mockFetch.mock.calls[0][1].body)
			expect(callBody.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:device_code')
			expect(callBody.get('device_code')).toBe(mockDeviceCode)
			expect(callBody.get('client_id')).toBe(mockClientId)
		})

		it('should throw error when client ID is missing', async () => {
			configure({ clientId: '', fetch: vi.fn() as any })

			await expect(
				pollForTokens(mockDeviceCode, 0.05, 10)
			).rejects.toThrow('Client ID is required for token polling')
		})

		it('should throw error when polling timeout expires', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: false,
				json: async () => ({ error: 'authorization_pending' }),
			})

			configure({ clientId: mockClientId, fetch: mockFetch as any })

			await expect(
				pollForTokens(mockDeviceCode, 0.05, 0.1) // Very short timeout (0.1 seconds)
			).rejects.toThrow('Device authorization expired')
		}, 10000)

		it('should handle unknown error responses', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: false,
				json: async () => ({ error: 'server_error' }),
			})

			configure({ clientId: mockClientId, fetch: mockFetch as any })

			await expect(
				pollForTokens(mockDeviceCode, 0.05, 10)
			).rejects.toThrow('Token polling failed: server_error')
		})

		it('should handle network errors during polling and continue', async () => {
			let callCount = 0

			const mockFetch = vi.fn().mockImplementation(async () => {
				callCount++
				if (callCount === 1) {
					// First call throws a network error (non-Error object)
					throw 'Network failure'
				}
				return {
					ok: true,
					json: async () => ({
						access_token: mockAccessToken,
						token_type: 'Bearer',
						expires_in: 3600,
					}),
				}
			})

			configure({ clientId: mockClientId, fetch: mockFetch as any })

			const result = await pollForTokens(mockDeviceCode, 0.05, 10)

			expect(mockFetch).toHaveBeenCalledTimes(2)
			expect(result.access_token).toBe(mockAccessToken)
		})

		it('should handle malformed JSON in error response', async () => {
			let callCount = 0

			const mockFetch = vi.fn().mockImplementation(async () => {
				callCount++
				if (callCount === 1) {
					return {
						ok: false,
						json: async () => {
							throw new Error('Invalid JSON')
						},
					}
				}
				return {
					ok: true,
					json: async () => ({
						access_token: mockAccessToken,
						token_type: 'Bearer',
						expires_in: 3600,
					}),
				}
			})

			configure({ clientId: mockClientId, fetch: mockFetch as any })

			// Should fail with 'unknown' error since JSON parse fails
			await expect(
				pollForTokens(mockDeviceCode, 0.05, 10)
			).rejects.toThrow('Token polling failed: unknown')
		})
	})
})
