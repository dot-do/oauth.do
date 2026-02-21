import { describe, it, expect } from 'vitest'
import {
	isUser,
	isLoginResponse,
	isTokenResponse,
	isDeviceAuthorizationResponse,
	isErrorResponse,
	isTokenError,
	toTokenError,
	isStoredTokenData,
	isGitHubDeviceAuthWireResponse,
	isGitHubTokenWireSuccess,
	isGitHubTokenWireError,
	toGitHubTokenError,
	isGitHubUserWireResponse,
	isVerifyResult,
	isWorkOSUserResponse,
	assertValid,
	ValidationError,
} from '../src/guards.js'

// ═══════════════════════════════════════════════════════════════════════════
// ValidationError
// ═══════════════════════════════════════════════════════════════════════════

describe('ValidationError', () => {
	it('should create with expected type and details', () => {
		const err = new ValidationError('TokenResponse', 'missing access_token', { foo: 1 })
		expect(err).toBeInstanceOf(Error)
		expect(err.name).toBe('ValidationError')
		expect(err.message).toBe('Invalid TokenResponse: missing access_token')
		expect(err.expectedType).toBe('TokenResponse')
		expect(err.details).toBe('missing access_token')
		expect(err.data).toEqual({ foo: 1 })
	})
})

describe('assertValid', () => {
	it('should return data when guard passes', () => {
		const data = { id: 'u1' }
		const result = assertValid(data, isUser, 'User')
		expect(result).toBe(data)
	})

	it('should throw ValidationError when guard fails', () => {
		expect(() => assertValid({ name: 'no id' }, isUser, 'User')).toThrow(ValidationError)
	})
})

// ═══════════════════════════════════════════════════════════════════════════
// isUser
// ═══════════════════════════════════════════════════════════════════════════

describe('isUser', () => {
	it('should accept valid user with only id', () => {
		expect(isUser({ id: 'user_1' })).toBe(true)
	})

	it('should accept user with optional fields', () => {
		expect(isUser({ id: 'user_1', email: 'a@b.com', name: 'Alice' })).toBe(true)
	})

	it('should accept user with extra fields (index signature)', () => {
		expect(isUser({ id: 'user_1', someExtra: true })).toBe(true)
	})

	it('should reject null', () => {
		expect(isUser(null)).toBe(false)
	})

	it('should reject non-object', () => {
		expect(isUser('string')).toBe(false)
		expect(isUser(42)).toBe(false)
		expect(isUser(undefined)).toBe(false)
	})

	it('should reject missing id', () => {
		expect(isUser({ email: 'a@b.com' })).toBe(false)
	})

	it('should reject non-string id', () => {
		expect(isUser({ id: 42 })).toBe(false)
	})

	it('should reject non-string email', () => {
		expect(isUser({ id: 'u1', email: 42 })).toBe(false)
	})

	it('should reject non-string name', () => {
		expect(isUser({ id: 'u1', name: 42 })).toBe(false)
	})
})

// ═══════════════════════════════════════════════════════════════════════════
// isLoginResponse
// ═══════════════════════════════════════════════════════════════════════════

describe('isLoginResponse', () => {
	it('should accept valid login response', () => {
		expect(isLoginResponse({ user: { id: 'u1' }, token: 'tok' })).toBe(true)
	})

	it('should reject missing token', () => {
		expect(isLoginResponse({ user: { id: 'u1' } })).toBe(false)
	})

	it('should reject missing user', () => {
		expect(isLoginResponse({ token: 'tok' })).toBe(false)
	})

	it('should reject invalid user', () => {
		expect(isLoginResponse({ user: { name: 'no id' }, token: 'tok' })).toBe(false)
	})

	it('should reject non-string token', () => {
		expect(isLoginResponse({ user: { id: 'u1' }, token: 42 })).toBe(false)
	})
})

// ═══════════════════════════════════════════════════════════════════════════
// isTokenResponse
// ═══════════════════════════════════════════════════════════════════════════

describe('isTokenResponse', () => {
	it('should accept minimal valid token response', () => {
		expect(isTokenResponse({ access_token: 'tok', token_type: 'Bearer' })).toBe(true)
	})

	it('should accept full token response', () => {
		expect(
			isTokenResponse({
				access_token: 'tok',
				token_type: 'Bearer',
				expires_in: 3600,
				refresh_token: 'ref',
				scope: 'openid',
				user: { id: 'u1' },
			})
		).toBe(true)
	})

	it('should reject missing access_token', () => {
		expect(isTokenResponse({ token_type: 'Bearer' })).toBe(false)
	})

	it('should accept missing token_type (WorkOS device flow omits it)', () => {
		expect(isTokenResponse({ access_token: 'tok' })).toBe(true)
	})

	it('should accept WorkOS device flow response shape', () => {
		expect(
			isTokenResponse({
				access_token: 'eyJ...',
				refresh_token: 'vb9hATCAYg0w...',
				authentication_method: 'GoogleOAuth',
				user: { id: 'user_01K7DHQ7BPSM64FWS1XV0ZVZZ1', email: 'test@example.com' },
			})
		).toBe(true)
	})

	it('should reject non-number expires_in', () => {
		expect(isTokenResponse({ access_token: 'tok', token_type: 'Bearer', expires_in: 'bad' })).toBe(false)
	})

	it('should reject non-string refresh_token', () => {
		expect(isTokenResponse({ access_token: 'tok', token_type: 'Bearer', refresh_token: 42 })).toBe(false)
	})

	it('should reject invalid user', () => {
		expect(isTokenResponse({ access_token: 'tok', token_type: 'Bearer', user: { name: 'no id' } })).toBe(false)
	})

	it('should reject null', () => {
		expect(isTokenResponse(null)).toBe(false)
	})

	it('should reject array', () => {
		expect(isTokenResponse([1, 2, 3])).toBe(false)
	})
})

// ═══════════════════════════════════════════════════════════════════════════
// isDeviceAuthorizationResponse
// ═══════════════════════════════════════════════════════════════════════════

describe('isDeviceAuthorizationResponse', () => {
	const valid = {
		device_code: 'dev123',
		user_code: 'ABCD-1234',
		verification_uri: 'https://example.com/activate',
		verification_uri_complete: 'https://example.com/activate?code=ABCD-1234',
		expires_in: 600,
		interval: 5,
	}

	it('should accept valid response', () => {
		expect(isDeviceAuthorizationResponse(valid)).toBe(true)
	})

	it('should reject missing device_code', () => {
		expect(isDeviceAuthorizationResponse({ ...valid, device_code: undefined })).toBe(false)
	})

	it('should reject missing user_code', () => {
		expect(isDeviceAuthorizationResponse({ ...valid, user_code: undefined })).toBe(false)
	})

	it('should reject missing verification_uri', () => {
		expect(isDeviceAuthorizationResponse({ ...valid, verification_uri: undefined })).toBe(false)
	})

	it('should reject missing expires_in', () => {
		expect(isDeviceAuthorizationResponse({ ...valid, expires_in: undefined })).toBe(false)
	})

	it('should reject non-number interval', () => {
		expect(isDeviceAuthorizationResponse({ ...valid, interval: 'bad' })).toBe(false)
	})

	it('should reject null', () => {
		expect(isDeviceAuthorizationResponse(null)).toBe(false)
	})
})

// ═══════════════════════════════════════════════════════════════════════════
// isErrorResponse
// ═══════════════════════════════════════════════════════════════════════════

describe('isErrorResponse', () => {
	it('should accept empty object', () => {
		expect(isErrorResponse({})).toBe(true)
	})

	it('should accept object with error string', () => {
		expect(isErrorResponse({ error: 'authorization_pending' })).toBe(true)
	})

	it('should accept object with undefined error', () => {
		expect(isErrorResponse({ error: undefined })).toBe(true)
	})

	it('should reject non-string error', () => {
		expect(isErrorResponse({ error: 42 })).toBe(false)
	})

	it('should reject null', () => {
		expect(isErrorResponse(null)).toBe(false)
	})
})

// ═══════════════════════════════════════════════════════════════════════════
// isTokenError / toTokenError
// ═══════════════════════════════════════════════════════════════════════════

describe('isTokenError', () => {
	it('should accept valid token errors', () => {
		expect(isTokenError('authorization_pending')).toBe(true)
		expect(isTokenError('slow_down')).toBe(true)
		expect(isTokenError('access_denied')).toBe(true)
		expect(isTokenError('expired_token')).toBe(true)
		expect(isTokenError('unknown')).toBe(true)
	})

	it('should reject invalid strings', () => {
		expect(isTokenError('not_a_real_error')).toBe(false)
	})

	it('should reject non-strings', () => {
		expect(isTokenError(42)).toBe(false)
		expect(isTokenError(null)).toBe(false)
	})
})

describe('toTokenError', () => {
	it('should return valid token errors unchanged', () => {
		expect(toTokenError('slow_down')).toBe('slow_down')
	})

	it('should return unknown for invalid values', () => {
		expect(toTokenError('not_real')).toBe('unknown')
		expect(toTokenError(42)).toBe('unknown')
		expect(toTokenError(null)).toBe('unknown')
	})
})

// ═══════════════════════════════════════════════════════════════════════════
// isStoredTokenData
// ═══════════════════════════════════════════════════════════════════════════

describe('isStoredTokenData', () => {
	it('should accept minimal stored token data', () => {
		expect(isStoredTokenData({ accessToken: 'tok' })).toBe(true)
	})

	it('should accept full stored token data', () => {
		expect(isStoredTokenData({ accessToken: 'tok', refreshToken: 'ref', expiresAt: 123 })).toBe(true)
	})

	it('should reject missing accessToken', () => {
		expect(isStoredTokenData({ refreshToken: 'ref' })).toBe(false)
	})

	it('should reject non-string accessToken', () => {
		expect(isStoredTokenData({ accessToken: 42 })).toBe(false)
	})

	it('should reject non-string refreshToken', () => {
		expect(isStoredTokenData({ accessToken: 'tok', refreshToken: 42 })).toBe(false)
	})

	it('should reject non-number expiresAt', () => {
		expect(isStoredTokenData({ accessToken: 'tok', expiresAt: 'bad' })).toBe(false)
	})

	it('should reject NaN expiresAt', () => {
		expect(isStoredTokenData({ accessToken: 'tok', expiresAt: NaN })).toBe(false)
	})

	it('should reject null', () => {
		expect(isStoredTokenData(null)).toBe(false)
	})
})

// ═══════════════════════════════════════════════════════════════════════════
// GitHub guards
// ═══════════════════════════════════════════════════════════════════════════

describe('isGitHubDeviceAuthWireResponse', () => {
	const valid = {
		device_code: 'dc',
		user_code: 'UC',
		verification_uri: 'https://github.com/login/device',
		expires_in: 900,
		interval: 5,
	}

	it('should accept valid response', () => {
		expect(isGitHubDeviceAuthWireResponse(valid)).toBe(true)
	})

	it('should reject missing device_code', () => {
		expect(isGitHubDeviceAuthWireResponse({ ...valid, device_code: undefined })).toBe(false)
	})

	it('should reject non-number expires_in', () => {
		expect(isGitHubDeviceAuthWireResponse({ ...valid, expires_in: 'bad' })).toBe(false)
	})
})

describe('isGitHubTokenWireSuccess', () => {
	it('should accept valid success', () => {
		expect(isGitHubTokenWireSuccess({ access_token: 'tok', token_type: 'bearer', scope: 'user' })).toBe(true)
	})

	it('should reject missing access_token', () => {
		expect(isGitHubTokenWireSuccess({ token_type: 'bearer', scope: 'user' })).toBe(false)
	})

	it('should reject missing scope', () => {
		expect(isGitHubTokenWireSuccess({ access_token: 'tok', token_type: 'bearer' })).toBe(false)
	})
})

describe('isGitHubTokenWireError', () => {
	it('should accept valid error', () => {
		expect(isGitHubTokenWireError({ error: 'authorization_pending' })).toBe(true)
	})

	it('should accept error with optional fields', () => {
		expect(isGitHubTokenWireError({ error: 'slow_down', error_description: 'too fast', error_uri: 'https://docs.github.com' })).toBe(true)
	})

	it('should reject missing error', () => {
		expect(isGitHubTokenWireError({})).toBe(false)
	})

	it('should reject non-string error_description', () => {
		expect(isGitHubTokenWireError({ error: 'x', error_description: 42 })).toBe(false)
	})
})

describe('toGitHubTokenError', () => {
	it('should return valid errors unchanged', () => {
		expect(toGitHubTokenError('slow_down')).toBe('slow_down')
		expect(toGitHubTokenError('authorization_pending')).toBe('authorization_pending')
	})

	it('should return unknown for invalid values', () => {
		expect(toGitHubTokenError('not_real')).toBe('unknown')
		expect(toGitHubTokenError(42)).toBe('unknown')
	})
})

describe('isGitHubUserWireResponse', () => {
	it('should accept valid user', () => {
		expect(
			isGitHubUserWireResponse({
				id: 12345,
				login: 'octocat',
				email: 'octocat@github.com',
				name: 'Octocat',
				avatar_url: 'https://avatars.githubusercontent.com/u/12345',
			})
		).toBe(true)
	})

	it('should accept user with null email and name', () => {
		expect(
			isGitHubUserWireResponse({
				id: 12345,
				login: 'octocat',
				email: null,
				name: null,
				avatar_url: 'https://avatars.githubusercontent.com/u/12345',
			})
		).toBe(true)
	})

	it('should reject non-number id', () => {
		expect(isGitHubUserWireResponse({ id: 'not-a-number', login: 'x', avatar_url: 'x' })).toBe(false)
	})

	it('should reject missing login', () => {
		expect(isGitHubUserWireResponse({ id: 1, avatar_url: 'x' })).toBe(false)
	})

	it('should reject missing avatar_url', () => {
		expect(isGitHubUserWireResponse({ id: 1, login: 'x' })).toBe(false)
	})

	it('should reject non-string email (not null)', () => {
		expect(isGitHubUserWireResponse({ id: 1, login: 'x', avatar_url: 'x', email: 42 })).toBe(false)
	})
})

// ═══════════════════════════════════════════════════════════════════════════
// Worker guards
// ═══════════════════════════════════════════════════════════════════════════

describe('isVerifyResult', () => {
	it('should accept valid result (valid: true)', () => {
		expect(isVerifyResult({ valid: true, user: { id: 'u1' } })).toBe(true)
	})

	it('should accept valid result (valid: false)', () => {
		expect(isVerifyResult({ valid: false, error: 'bad token' })).toBe(true)
	})

	it('should accept result with cached flag', () => {
		expect(isVerifyResult({ valid: true, cached: true })).toBe(true)
	})

	it('should reject missing valid field', () => {
		expect(isVerifyResult({ error: 'bad' })).toBe(false)
	})

	it('should reject non-boolean valid', () => {
		expect(isVerifyResult({ valid: 'true' })).toBe(false)
	})

	it('should reject user without id', () => {
		expect(isVerifyResult({ valid: true, user: { name: 'no id' } })).toBe(false)
	})

	it('should reject non-object user', () => {
		expect(isVerifyResult({ valid: true, user: 'not-object' })).toBe(false)
	})
})

describe('isWorkOSUserResponse', () => {
	it('should accept valid response', () => {
		expect(isWorkOSUserResponse({ id: 'u1', email: 'a@b.com' })).toBe(true)
	})

	it('should accept with optional names', () => {
		expect(isWorkOSUserResponse({ id: 'u1', email: 'a@b.com', first_name: 'A', last_name: 'B' })).toBe(true)
	})

	it('should reject missing id', () => {
		expect(isWorkOSUserResponse({ email: 'a@b.com' })).toBe(false)
	})

	it('should reject missing email', () => {
		expect(isWorkOSUserResponse({ id: 'u1' })).toBe(false)
	})

	it('should reject non-string first_name', () => {
		expect(isWorkOSUserResponse({ id: 'u1', email: 'a@b.com', first_name: 42 })).toBe(false)
	})
})
