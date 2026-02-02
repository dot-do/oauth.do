import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  encodeSession,
  decodeSession,
  isValidSessionData,
  getSessionConfig,
  defaultSessionConfig,
} from '../src/session'
import type { SessionData } from '../src/session'

// Helper to reset module state between tests
const originalEnv = process.env.NODE_ENV

describe('Session Encryption', () => {
  const testSecret = 'test-secret-key-for-testing'
  const validSession: SessionData = {
    userId: 'user_123',
    accessToken: 'tok_abc123',
    email: 'alice@example.com',
    name: 'Alice',
    organizationId: 'org_456',
    refreshToken: 'ref_xyz',
    expiresAt: Date.now() + 3600000,
  }

  describe('encodeSession / decodeSession', () => {
    it('roundtrips session data', async () => {
      const encoded = await encodeSession(validSession, testSecret)
      const decoded = await decodeSession(encoded, testSecret)

      expect(decoded).toEqual(validSession)
    })

    it('produces different ciphertext each time (random IV)', async () => {
      const encoded1 = await encodeSession(validSession, testSecret)
      const encoded2 = await encodeSession(validSession, testSecret)

      expect(encoded1).not.toBe(encoded2)
    })

    it('returns null for invalid ciphertext', async () => {
      const result = await decodeSession('not-valid-base64!!!', testSecret)
      expect(result).toBeNull()
    })

    it('returns null for wrong secret', async () => {
      const encoded = await encodeSession(validSession, testSecret)
      const decoded = await decodeSession(encoded, 'wrong-secret')

      expect(decoded).toBeNull()
    })

    it('handles minimal session data', async () => {
      const minimal: SessionData = {
        userId: 'u1',
        accessToken: 'tok',
      }
      const encoded = await encodeSession(minimal, testSecret)
      const decoded = await decodeSession(encoded, testSecret)

      expect(decoded).toEqual(minimal)
    })

    it('uses generated dev secret when not provided in non-production', async () => {
      // In non-production (test) mode, a random secret is generated and cached
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

      const encoded = await encodeSession(validSession)
      const decoded = await decodeSession(encoded)

      expect(decoded).toEqual(validSession)
      warnSpy.mockRestore()
    })

    it('preserves custom extensible fields', async () => {
      const extended: SessionData = {
        userId: 'u1',
        accessToken: 'tok',
        customField: 'custom-value',
        numericField: 42,
      }
      const encoded = await encodeSession(extended, testSecret)
      const decoded = await decodeSession(encoded, testSecret)

      expect(decoded).toEqual(extended)
    })
  })

  describe('isValidSessionData', () => {
    it('validates required fields', () => {
      expect(isValidSessionData({ userId: 'u1', accessToken: 'tok' })).toBe(true)
      expect(isValidSessionData({ userId: '', accessToken: 'tok' })).toBe(false)
      expect(isValidSessionData({ userId: 'u1', accessToken: '' })).toBe(false)
      expect(isValidSessionData({ userId: 'u1' })).toBe(false)
      expect(isValidSessionData({ accessToken: 'tok' })).toBe(false)
    })

    it('rejects non-objects', () => {
      expect(isValidSessionData(null)).toBe(false)
      expect(isValidSessionData(undefined)).toBe(false)
      expect(isValidSessionData('string')).toBe(false)
      expect(isValidSessionData(42)).toBe(false)
    })

    it('validates optional field types', () => {
      expect(isValidSessionData({
        userId: 'u1',
        accessToken: 'tok',
        organizationId: 123, // should be string
      })).toBe(false)

      expect(isValidSessionData({
        userId: 'u1',
        accessToken: 'tok',
        email: 123, // should be string
      })).toBe(false)

      expect(isValidSessionData({
        userId: 'u1',
        accessToken: 'tok',
        expiresAt: '123', // should be number
      })).toBe(false)
    })

    it('allows valid optional fields', () => {
      expect(isValidSessionData({
        userId: 'u1',
        accessToken: 'tok',
        organizationId: 'org_1',
        email: 'a@b.com',
        name: 'Alice',
        refreshToken: 'ref',
        expiresAt: 123456,
      })).toBe(true)
    })
  })

  describe('getSessionConfig', () => {
    beforeEach(() => {
      // Ensure we're not in production for these tests
      process.env.NODE_ENV = 'test'
    })

    afterEach(() => {
      process.env.NODE_ENV = originalEnv
    })

    it('returns defaults with generated secret when no env provided in non-production', () => {
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
      const config = getSessionConfig()

      // Should have all default values except secret which is generated
      expect(config.cookieName).toBe(defaultSessionConfig.cookieName)
      expect(config.cookieMaxAge).toBe(defaultSessionConfig.cookieMaxAge)
      expect(config.cookieSecure).toBe(defaultSessionConfig.cookieSecure)
      expect(config.cookieSameSite).toBe(defaultSessionConfig.cookieSameSite)
      // Secret should be a generated hex string (64 chars for 32 bytes)
      expect(typeof config.secret).toBe('string')
      expect(config.secret.length).toBeGreaterThan(0)

      warnSpy.mockRestore()
    })

    it('throws error in production when SESSION_SECRET not provided', () => {
      process.env.NODE_ENV = 'production'

      expect(() => getSessionConfig()).toThrow(
        'SESSION_SECRET environment variable is required in production'
      )
    })

    it('reads SESSION_SECRET from env', () => {
      const config = getSessionConfig({ SESSION_SECRET: 'my-secret' })
      expect(config.secret).toBe('my-secret')
    })

    it('reads SESSION_COOKIE_NAME from env', () => {
      const config = getSessionConfig({ SESSION_SECRET: 'test-secret', SESSION_COOKIE_NAME: 'my_session' })
      expect(config.cookieName).toBe('my_session')
    })

    it('reads SESSION_COOKIE_MAX_AGE from env', () => {
      const config = getSessionConfig({ SESSION_SECRET: 'test-secret', SESSION_COOKIE_MAX_AGE: '3600' })
      expect(config.cookieMaxAge).toBe(3600)
    })

    it('ignores invalid max age', () => {
      const config = getSessionConfig({ SESSION_SECRET: 'test-secret', SESSION_COOKIE_MAX_AGE: 'not-a-number' })
      expect(config.cookieMaxAge).toBe(defaultSessionConfig.cookieMaxAge)
    })

    it('ignores negative max age', () => {
      const config = getSessionConfig({ SESSION_SECRET: 'test-secret', SESSION_COOKIE_MAX_AGE: '-1' })
      expect(config.cookieMaxAge).toBe(defaultSessionConfig.cookieMaxAge)
    })

    it('reads SESSION_COOKIE_SECURE from env', () => {
      const config = getSessionConfig({ SESSION_SECRET: 'test-secret', SESSION_COOKIE_SECURE: 'false' })
      expect(config.cookieSecure).toBe(false)
    })

    it('reads SESSION_COOKIE_SAME_SITE from env', () => {
      expect(getSessionConfig({ SESSION_SECRET: 'test-secret', SESSION_COOKIE_SAME_SITE: 'strict' }).cookieSameSite).toBe('strict')
      expect(getSessionConfig({ SESSION_SECRET: 'test-secret', SESSION_COOKIE_SAME_SITE: 'none' }).cookieSameSite).toBe('none')
    })

    it('ignores invalid same site values', () => {
      const config = getSessionConfig({ SESSION_SECRET: 'test-secret', SESSION_COOKIE_SAME_SITE: 'invalid' })
      expect(config.cookieSameSite).toBe('lax')
    })
  })
})
