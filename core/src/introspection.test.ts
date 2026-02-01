import { describe, it, expect, vi, beforeEach } from 'vitest'
import { createOAuth21Server } from './server.js'
import type { OAuthStorage } from './storage.js'
import type { OAuthAccessToken } from './types.js'
import { SigningKeyManager, type SigningKey, generateSigningKey, signAccessToken } from './jwt-signing.js'

// Helper: decode base64url string to bytes
function base64UrlDecode(s: string): Uint8Array {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice(0, (4 - (s.length % 4)) % 4)
  const binary = atob(padded)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

// Helper: decode JWT parts
function decodeJwt(token: string) {
  const [headerB64, payloadB64, signatureB64] = token.split('.')
  const header = JSON.parse(new TextDecoder().decode(base64UrlDecode(headerB64!)))
  const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64!)))
  return { header, payload, signatureB64: signatureB64!, headerB64: headerB64!, payloadB64: payloadB64! }
}

// Mock storage implementation for testing
function createMockStorage(): OAuthStorage {
  const accessTokens = new Map<string, OAuthAccessToken>()
  const clients = new Map<string, any>()
  const users = new Map<string, any>()

  return {
    // Access token operations
    getAccessToken: vi.fn(async (token: string) => {
      return accessTokens.get(token) || null
    }),
    saveAccessToken: vi.fn(async (token: OAuthAccessToken) => {
      accessTokens.set(token.token, token)
    }),
    revokeAccessToken: vi.fn(async (token: string) => {
      accessTokens.delete(token)
    }),

    // Client operations
    getClient: vi.fn(async (clientId: string) => {
      return clients.get(clientId) || null
    }),
    saveClient: vi.fn(async (client: any) => {
      clients.set(client.clientId, client)
    }),

    // User operations
    getUser: vi.fn(async (id: string) => {
      return users.get(id) || null
    }),
    getUserByEmail: vi.fn(async (email: string) => {
      for (const user of users.values()) {
        if (user.email === email) return user
      }
      return null
    }),
    saveUser: vi.fn(async (user: any) => {
      users.set(user.id, user)
    }),

    // Stubs for other required methods
    getUserByProvider: vi.fn(async () => null),
    deleteUser: vi.fn(async () => {}),
    listUsers: vi.fn(async () => []),
    getOrganization: vi.fn(async () => null),
    getOrganizationBySlug: vi.fn(async () => null),
    getOrganizationByDomain: vi.fn(async () => null),
    saveOrganization: vi.fn(async () => {}),
    deleteOrganization: vi.fn(async () => {}),
    listOrganizations: vi.fn(async () => []),
    deleteClient: vi.fn(async () => {}),
    listClients: vi.fn(async () => []),
    saveAuthorizationCode: vi.fn(async () => {}),
    getAuthorizationCode: vi.fn(async () => null),
    consumeAuthorizationCode: vi.fn(async () => null),
    getRefreshToken: vi.fn(async () => null),
    saveRefreshToken: vi.fn(async () => {}),
    revokeRefreshToken: vi.fn(async () => {}),
    getGrant: vi.fn(async () => null),
    saveGrant: vi.fn(async () => {}),
    revokeGrant: vi.fn(async () => {}),
    listGrants: vi.fn(async () => []),
  }
}

describe('/introspect endpoint', () => {
  let storage: OAuthStorage
  let signingKeyManager: SigningKeyManager
  let signingKey: SigningKey
  const issuer = 'https://oauth.test'

  beforeEach(async () => {
    storage = createMockStorage()
    signingKeyManager = new SigningKeyManager()
    signingKey = await signingKeyManager.getCurrentKey()
  })

  describe('JWT token introspection', () => {
    it('returns active=true with claims for valid JWT token', async () => {
      const app = createOAuth21Server({
        issuer,
        storage,
        devMode: { enabled: true },
        signingKeyManager,
        useJwtAccessTokens: true,
      })

      // Generate a valid JWT
      const token = await signAccessToken(
        signingKey,
        {
          sub: 'user-123',
          client_id: 'client-abc',
          scope: 'read write',
        },
        {
          issuer,
          audience: 'client-abc',
          expiresIn: 3600,
        }
      )

      const res = await app.request('/introspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token }).toString(),
      })

      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.active).toBe(true)
      expect(data.sub).toBe('user-123')
      expect(data.client_id).toBe('client-abc')
      expect(data.scope).toBe('read write')
      expect(data.token_type).toBe('Bearer')
      expect(data.exp).toBeDefined()
      expect(data.iat).toBeDefined()
      expect(data.iss).toBe(issuer)
    })

    it('returns active=true for JWT with JSON request body', async () => {
      const app = createOAuth21Server({
        issuer,
        storage,
        devMode: { enabled: true },
        signingKeyManager,
        useJwtAccessTokens: true,
      })

      const token = await signAccessToken(
        signingKey,
        { sub: 'user-1', client_id: 'client-1' },
        { issuer }
      )

      const res = await app.request('/introspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token }),
      })

      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.active).toBe(true)
      expect(data.sub).toBe('user-1')
      expect(data.client_id).toBe('client-1')
    })

    it('returns active=false for expired JWT token', async () => {
      const app = createOAuth21Server({
        issuer,
        storage,
        devMode: { enabled: true },
        signingKeyManager,
        useJwtAccessTokens: true,
      })

      // Generate an expired JWT (expired 1 hour ago)
      const token = await signAccessToken(
        signingKey,
        { sub: 'user-123', client_id: 'client-abc' },
        { issuer, expiresIn: -3600 }
      )

      const res = await app.request('/introspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token }).toString(),
      })

      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.active).toBe(false)
    })

    it('returns active=false for JWT with invalid signature', async () => {
      const app = createOAuth21Server({
        issuer,
        storage,
        devMode: { enabled: true },
        signingKeyManager,
        useJwtAccessTokens: true,
      })

      // Generate a valid JWT
      const validToken = await signAccessToken(
        signingKey,
        { sub: 'user-123', client_id: 'client-abc' },
        { issuer }
      )

      // Tamper with the signature
      const parts = validToken.split('.')
      const tamperedToken = `${parts[0]}.${parts[1]}.invalidsignature`

      const res = await app.request('/introspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: tamperedToken }).toString(),
      })

      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.active).toBe(false)
    })

    it('returns active=false for JWT with wrong issuer', async () => {
      const app = createOAuth21Server({
        issuer,
        storage,
        devMode: { enabled: true },
        signingKeyManager,
        useJwtAccessTokens: true,
      })

      // Generate JWT with wrong issuer
      const token = await signAccessToken(
        signingKey,
        { sub: 'user-123', client_id: 'client-abc' },
        { issuer: 'https://wrong-issuer.com' }
      )

      const res = await app.request('/introspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token }).toString(),
      })

      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.active).toBe(false)
    })

    it('respects X-Issuer header for multi-tenant scenarios', async () => {
      const app = createOAuth21Server({
        issuer,
        storage,
        devMode: { enabled: true },
        signingKeyManager,
        useJwtAccessTokens: true,
      })

      const effectiveIssuer = 'https://tenant.example.com'

      // Generate JWT with tenant issuer
      const token = await signAccessToken(
        signingKey,
        { sub: 'user-123', client_id: 'client-abc' },
        { issuer: effectiveIssuer }
      )

      const res = await app.request('/introspect', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'X-Issuer': effectiveIssuer,
        },
        body: new URLSearchParams({ token }).toString(),
      })

      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.active).toBe(true)
      expect(data.iss).toBe(effectiveIssuer)
    })
  })

  describe('Opaque token introspection', () => {
    it('returns active=true with claims for valid opaque token', async () => {
      const app = createOAuth21Server({
        issuer,
        storage,
        devMode: { enabled: true },
      })

      const opaqueToken = 'opaque-token-abc123'
      const now = Date.now()

      // Store an opaque token
      await storage.saveAccessToken({
        token: opaqueToken,
        tokenType: 'Bearer',
        clientId: 'client-xyz',
        userId: 'user-456',
        scope: 'openid profile',
        issuedAt: now,
        expiresAt: now + 3600 * 1000, // 1 hour from now
      })

      const res = await app.request('/introspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: opaqueToken }).toString(),
      })

      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.active).toBe(true)
      expect(data.sub).toBe('user-456')
      expect(data.client_id).toBe('client-xyz')
      expect(data.scope).toBe('openid profile')
      expect(data.token_type).toBe('Bearer')
      expect(data.exp).toBeDefined()
      expect(data.iat).toBeDefined()
    })

    it('returns active=false for expired opaque token', async () => {
      const app = createOAuth21Server({
        issuer,
        storage,
        devMode: { enabled: true },
      })

      const opaqueToken = 'expired-opaque-token'
      const now = Date.now()

      // Store an expired opaque token
      await storage.saveAccessToken({
        token: opaqueToken,
        tokenType: 'Bearer',
        clientId: 'client-xyz',
        userId: 'user-456',
        scope: 'openid',
        issuedAt: now - 7200 * 1000, // 2 hours ago
        expiresAt: now - 3600 * 1000, // Expired 1 hour ago
      })

      const res = await app.request('/introspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: opaqueToken }).toString(),
      })

      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.active).toBe(false)
    })

    it('returns active=false for non-existent opaque token', async () => {
      const app = createOAuth21Server({
        issuer,
        storage,
        devMode: { enabled: true },
      })

      const res = await app.request('/introspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: 'non-existent-token' }).toString(),
      })

      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.active).toBe(false)
    })
  })

  describe('Error cases', () => {
    it('returns active=false when token is missing', async () => {
      const app = createOAuth21Server({
        issuer,
        storage,
        devMode: { enabled: true },
        signingKeyManager,
        useJwtAccessTokens: true,
      })

      const res = await app.request('/introspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({}).toString(),
      })

      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.active).toBe(false)
    })

    it('returns active=false when token is empty string', async () => {
      const app = createOAuth21Server({
        issuer,
        storage,
        devMode: { enabled: true },
        signingKeyManager,
        useJwtAccessTokens: true,
      })

      const res = await app.request('/introspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: '' }).toString(),
      })

      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.active).toBe(false)
    })

    it('returns active=false for malformed JWT (invalid format)', async () => {
      const app = createOAuth21Server({
        issuer,
        storage,
        devMode: { enabled: true },
        signingKeyManager,
        useJwtAccessTokens: true,
      })

      const res = await app.request('/introspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: 'this.is.not.a.valid.jwt' }).toString(),
      })

      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.active).toBe(false)
    })

    it('returns active=false for JWT when no signing key manager is configured', async () => {
      const app = createOAuth21Server({
        issuer,
        storage,
        devMode: { enabled: true },
        // No signingKeyManager or useJwtAccessTokens
      })

      // Generate a JWT (but server has no key to verify it)
      const token = await signAccessToken(
        signingKey,
        { sub: 'user-123', client_id: 'client-abc' },
        { issuer }
      )

      const res = await app.request('/introspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token }).toString(),
      })

      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.active).toBe(false)
    })
  })

  describe('Client authentication (future extension)', () => {
    // The current implementation doesn't require client authentication for introspection,
    // but these tests document expected behavior if authentication is added

    it('introspects token without client authentication (current behavior)', async () => {
      const app = createOAuth21Server({
        issuer,
        storage,
        devMode: { enabled: true },
        signingKeyManager,
        useJwtAccessTokens: true,
      })

      const token = await signAccessToken(
        signingKey,
        { sub: 'user-123', client_id: 'client-abc' },
        { issuer }
      )

      // No Authorization header or client credentials
      const res = await app.request('/introspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token }).toString(),
      })

      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.active).toBe(true)
    })
  })

  describe('Content-Type handling', () => {
    it('accepts application/x-www-form-urlencoded', async () => {
      const app = createOAuth21Server({
        issuer,
        storage,
        devMode: { enabled: true },
        signingKeyManager,
        useJwtAccessTokens: true,
      })

      const token = await signAccessToken(
        signingKey,
        { sub: 'user-1', client_id: 'client-1' },
        { issuer }
      )

      const res = await app.request('/introspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token }).toString(),
      })

      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.active).toBe(true)
    })

    it('accepts application/json', async () => {
      const app = createOAuth21Server({
        issuer,
        storage,
        devMode: { enabled: true },
        signingKeyManager,
        useJwtAccessTokens: true,
      })

      const token = await signAccessToken(
        signingKey,
        { sub: 'user-1', client_id: 'client-1' },
        { issuer }
      )

      const res = await app.request('/introspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token }),
      })

      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.active).toBe(true)
    })
  })

  describe('Edge cases', () => {
    it('handles JWT with minimal claims', async () => {
      const app = createOAuth21Server({
        issuer,
        storage,
        devMode: { enabled: true },
        signingKeyManager,
        useJwtAccessTokens: true,
      })

      const token = await signAccessToken(
        signingKey,
        { sub: 'user-1', client_id: 'client-1' },
        { issuer }
      )

      const res = await app.request('/introspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token }),
      })

      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.active).toBe(true)
      expect(data.sub).toBe('user-1')
      expect(data.client_id).toBe('client-1')
      // No scope should be undefined or omitted
    })

    it('handles JWT with additional custom claims', async () => {
      const app = createOAuth21Server({
        issuer,
        storage,
        devMode: { enabled: true },
        signingKeyManager,
        useJwtAccessTokens: true,
      })

      const token = await signAccessToken(
        signingKey,
        {
          sub: 'user-1',
          client_id: 'client-1',
          scope: 'read',
          custom_claim: 'custom_value',
          org_id: 'org-123',
        },
        { issuer }
      )

      const res = await app.request('/introspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token }),
      })

      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.active).toBe(true)
      expect(data.sub).toBe('user-1')
      expect(data.scope).toBe('read')
      // Note: The introspection endpoint only returns standard claims,
      // not custom claims like org_id
    })

    it('handles opaque token with no scope', async () => {
      const app = createOAuth21Server({
        issuer,
        storage,
        devMode: { enabled: true },
      })

      const opaqueToken = 'token-no-scope'
      const now = Date.now()

      await storage.saveAccessToken({
        token: opaqueToken,
        tokenType: 'Bearer',
        clientId: 'client-1',
        userId: 'user-1',
        // No scope field
        issuedAt: now,
        expiresAt: now + 3600 * 1000,
      })

      const res = await app.request('/introspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: opaqueToken }),
      })

      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.active).toBe(true)
      expect(data.scope).toBeUndefined()
    })
  })
})
