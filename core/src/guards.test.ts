import { describe, it, expect } from 'vitest'
import {
  isStripeWebhookEvent,
  isStripeApiError,
  isJWTHeader,
  isJWTPayload,
  isSerializedSigningKey,
  isStringArray,
  isIntrospectionResponse,
  assertValid,
  ValidationError,
} from './guards.js'

// ═══════════════════════════════════════════════════════════════════════════
// ValidationError
// ═══════════════════════════════════════════════════════════════════════════

describe('ValidationError', () => {
  it('should create with expected type and details', () => {
    const err = new ValidationError('StripeWebhookEvent', 'missing id', { foo: 1 })
    expect(err).toBeInstanceOf(Error)
    expect(err.name).toBe('ValidationError')
    expect(err.expectedType).toBe('StripeWebhookEvent')
    expect(err.details).toBe('missing id')
  })
})

describe('assertValid', () => {
  it('should return data when guard passes', () => {
    const data = { alg: 'RS256' }
    const result = assertValid(data, isJWTHeader, 'JWTHeader')
    expect(result).toBe(data)
  })

  it('should throw ValidationError when guard fails', () => {
    expect(() => assertValid({}, isJWTHeader, 'JWTHeader')).toThrow(ValidationError)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// isStripeWebhookEvent
// ═══════════════════════════════════════════════════════════════════════════

describe('isStripeWebhookEvent', () => {
  const valid = {
    id: 'evt_123',
    type: 'customer.created',
    data: { object: { id: 'cus_123' } },
  }

  it('should accept valid event', () => {
    expect(isStripeWebhookEvent(valid)).toBe(true)
  })

  it('should accept all supported event types', () => {
    const types = [
      'customer.created',
      'customer.updated',
      'customer.deleted',
      'customer.subscription.created',
      'customer.subscription.updated',
      'customer.subscription.deleted',
      'invoice.paid',
      'invoice.payment_failed',
    ]
    for (const type of types) {
      expect(isStripeWebhookEvent({ ...valid, type })).toBe(true)
    }
  })

  it('should reject unsupported event type', () => {
    expect(isStripeWebhookEvent({ ...valid, type: 'checkout.session.completed' })).toBe(false)
  })

  it('should reject missing id', () => {
    expect(isStripeWebhookEvent({ type: 'customer.created', data: { object: {} } })).toBe(false)
  })

  it('should reject missing type', () => {
    expect(isStripeWebhookEvent({ id: 'evt_123', data: { object: {} } })).toBe(false)
  })

  it('should reject missing data.object', () => {
    expect(isStripeWebhookEvent({ id: 'evt_123', type: 'customer.created', data: {} })).toBe(false)
  })

  it('should reject non-object data', () => {
    expect(isStripeWebhookEvent({ id: 'evt_123', type: 'customer.created', data: 'bad' })).toBe(false)
  })

  it('should reject null', () => {
    expect(isStripeWebhookEvent(null)).toBe(false)
  })

  it('should reject string', () => {
    expect(isStripeWebhookEvent('{"id":"evt_123"}')).toBe(false)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// isStripeApiError
// ═══════════════════════════════════════════════════════════════════════════

describe('isStripeApiError', () => {
  it('should accept empty object (no error key)', () => {
    expect(isStripeApiError({})).toBe(true)
  })

  it('should accept error with message', () => {
    expect(isStripeApiError({ error: { message: 'Not found' } })).toBe(true)
  })

  it('should accept error without message', () => {
    expect(isStripeApiError({ error: {} })).toBe(true)
  })

  it('should reject error with non-string message', () => {
    expect(isStripeApiError({ error: { message: 42 } })).toBe(false)
  })

  it('should reject non-object error', () => {
    expect(isStripeApiError({ error: 'bad' })).toBe(false)
  })

  it('should reject null', () => {
    expect(isStripeApiError(null)).toBe(false)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// isJWTHeader
// ═══════════════════════════════════════════════════════════════════════════

describe('isJWTHeader', () => {
  it('should accept minimal header', () => {
    expect(isJWTHeader({ alg: 'RS256' })).toBe(true)
  })

  it('should accept full header', () => {
    expect(isJWTHeader({ alg: 'RS256', typ: 'JWT', kid: 'key1' })).toBe(true)
  })

  it('should reject missing alg', () => {
    expect(isJWTHeader({ typ: 'JWT' })).toBe(false)
  })

  it('should reject non-string alg', () => {
    expect(isJWTHeader({ alg: 256 })).toBe(false)
  })

  it('should reject non-string typ', () => {
    expect(isJWTHeader({ alg: 'RS256', typ: 42 })).toBe(false)
  })

  it('should reject non-string kid', () => {
    expect(isJWTHeader({ alg: 'RS256', kid: 42 })).toBe(false)
  })

  it('should reject null', () => {
    expect(isJWTHeader(null)).toBe(false)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// isJWTPayload
// ═══════════════════════════════════════════════════════════════════════════

describe('isJWTPayload', () => {
  it('should accept empty object (all fields optional)', () => {
    expect(isJWTPayload({})).toBe(true)
  })

  it('should accept full payload', () => {
    expect(
      isJWTPayload({
        iss: 'https://auth.example.com',
        sub: 'user_1',
        aud: 'client_1',
        exp: Math.floor(Date.now() / 1000) + 3600,
        nbf: Math.floor(Date.now() / 1000),
        iat: Math.floor(Date.now() / 1000),
        jti: 'jwt_123',
      })
    ).toBe(true)
  })

  it('should accept string aud', () => {
    expect(isJWTPayload({ aud: 'client_1' })).toBe(true)
  })

  it('should accept string[] aud', () => {
    expect(isJWTPayload({ aud: ['client_1', 'client_2'] })).toBe(true)
  })

  it('should reject non-string iss', () => {
    expect(isJWTPayload({ iss: 42 })).toBe(false)
  })

  it('should reject non-number exp', () => {
    expect(isJWTPayload({ exp: 'bad' })).toBe(false)
  })

  it('should reject NaN exp', () => {
    expect(isJWTPayload({ exp: NaN })).toBe(false)
  })

  it('should reject non-string sub', () => {
    expect(isJWTPayload({ sub: 42 })).toBe(false)
  })

  it('should reject aud with non-string array elements', () => {
    expect(isJWTPayload({ aud: ['ok', 42] })).toBe(false)
  })

  it('should reject non-string/non-array aud', () => {
    expect(isJWTPayload({ aud: 42 })).toBe(false)
  })

  it('should accept extra claims', () => {
    expect(isJWTPayload({ sub: 'u1', custom_claim: 'value' })).toBe(true)
  })

  it('should reject null', () => {
    expect(isJWTPayload(null)).toBe(false)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// isSerializedSigningKey
// ═══════════════════════════════════════════════════════════════════════════

describe('isSerializedSigningKey', () => {
  const valid = {
    kid: 'key1',
    alg: 'RS256' as const,
    privateKeyJwk: { kty: 'RSA', n: 'abc', e: 'AQAB' },
    publicKeyJwk: { kty: 'RSA', n: 'abc', e: 'AQAB' },
    createdAt: Date.now(),
  }

  it('should accept valid key', () => {
    expect(isSerializedSigningKey(valid)).toBe(true)
  })

  it('should reject missing kid', () => {
    expect(isSerializedSigningKey({ ...valid, kid: undefined })).toBe(false)
  })

  it('should reject wrong alg', () => {
    expect(isSerializedSigningKey({ ...valid, alg: 'HS256' })).toBe(false)
  })

  it('should reject missing privateKeyJwk', () => {
    expect(isSerializedSigningKey({ ...valid, privateKeyJwk: undefined })).toBe(false)
  })

  it('should reject non-object publicKeyJwk', () => {
    expect(isSerializedSigningKey({ ...valid, publicKeyJwk: 'bad' })).toBe(false)
  })

  it('should reject non-number createdAt', () => {
    expect(isSerializedSigningKey({ ...valid, createdAt: 'bad' })).toBe(false)
  })

  it('should reject null', () => {
    expect(isSerializedSigningKey(null)).toBe(false)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// isStringArray
// ═══════════════════════════════════════════════════════════════════════════

describe('isStringArray', () => {
  it('should accept empty array', () => {
    expect(isStringArray([])).toBe(true)
  })

  it('should accept string array', () => {
    expect(isStringArray(['a', 'b', 'c'])).toBe(true)
  })

  it('should reject mixed array', () => {
    expect(isStringArray(['a', 42])).toBe(false)
  })

  it('should reject number array', () => {
    expect(isStringArray([1, 2, 3])).toBe(false)
  })

  it('should reject string (not an array)', () => {
    expect(isStringArray('abc')).toBe(false)
  })

  it('should reject null', () => {
    expect(isStringArray(null)).toBe(false)
  })

  it('should reject object', () => {
    expect(isStringArray({ 0: 'a' })).toBe(false)
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// isIntrospectionResponse
// ═══════════════════════════════════════════════════════════════════════════

describe('isIntrospectionResponse', () => {
  it('should accept minimal response (active: false)', () => {
    expect(isIntrospectionResponse({ active: false })).toBe(true)
  })

  it('should accept full response', () => {
    expect(
      isIntrospectionResponse({
        active: true,
        sub: 'user_1',
        client_id: 'client_1',
        scope: 'openid',
        exp: 1000000,
        iat: 999999,
        iss: 'https://auth.example.com',
      })
    ).toBe(true)
  })

  it('should reject missing active', () => {
    expect(isIntrospectionResponse({ sub: 'u1' })).toBe(false)
  })

  it('should reject non-boolean active', () => {
    expect(isIntrospectionResponse({ active: 'true' })).toBe(false)
  })

  it('should reject non-string sub', () => {
    expect(isIntrospectionResponse({ active: true, sub: 42 })).toBe(false)
  })

  it('should reject non-number exp', () => {
    expect(isIntrospectionResponse({ active: true, exp: 'bad' })).toBe(false)
  })

  it('should reject null', () => {
    expect(isIntrospectionResponse(null)).toBe(false)
  })
})
