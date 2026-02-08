/**
 * OAuth Worker Integration Tests
 *
 * Tests the actual HTTP endpoints of the oauth.do worker using
 * MemoryOAuthStorage and devMode (no real Durable Object or upstream provider).
 *
 * These tests exercise the full OAuth 2.1 endpoint surface:
 * - POST /token (authorization_code grant, refresh_token grant)
 * - GET /authorize (authorization request with PKCE)
 * - GET /.well-known/oauth-authorization-server (OIDC-style discovery)
 * - POST /register (Dynamic Client Registration — RFC 7591)
 * - POST /introspect (Token introspection — RFC 7662)
 * - POST /revoke (Token revocation — RFC 7009)
 * - Error cases (invalid grant, expired token, bad client)
 *
 * Each test is self-contained: it registers its own clients and creates tokens.
 *
 * Uses @dotdo/oauth npm package with MemoryOAuthStorage + devMode.
 */

import { describe, it, expect, beforeEach } from 'vitest'
import {
  createOAuth21Server,
  MemoryOAuthStorage,
  generateCodeVerifier,
  generateCodeChallenge,
} from '@dotdo/oauth'
import type { OAuth21Server } from '@dotdo/oauth'

/**
 * Helper to register a public client (no secret required)
 */
async function registerPublicClient(
  server: OAuth21Server,
  name = 'Test Client',
  redirectUri = 'https://example.com/callback'
): Promise<{ client_id: string; client_secret: string }> {
  const res = await server.request('/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_name: name,
      redirect_uris: [redirectUri],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
    }),
  })
  expect(res.status).toBe(201)
  return res.json()
}

/**
 * Helper to register a confidential client (secret required)
 */
async function registerConfidentialClient(
  server: OAuth21Server,
  name = 'Confidential Client',
  redirectUri = 'https://confidential.example.com/callback'
): Promise<{ client_id: string; client_secret: string }> {
  const res = await server.request('/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_name: name,
      redirect_uris: [redirectUri],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_post',
    }),
  })
  expect(res.status).toBe(201)
  return res.json()
}

/**
 * Helper to complete the authorization code flow and return tokens.
 * Performs login via devMode POST /login and token exchange.
 */
async function getTokensViaAuthCodeFlow(
  server: OAuth21Server,
  clientId: string,
  redirectUri = 'https://example.com/callback',
  scope = 'openid profile'
): Promise<{
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
  scope?: string
}> {
  const codeVerifier = generateCodeVerifier()
  const codeChallenge = await generateCodeChallenge(codeVerifier)

  // Login to get auth code
  const loginRes = await server.request('/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      email: 'test@example.com',
      password: 'test123',
      client_id: clientId,
      redirect_uri: redirectUri,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      state: 'integration-test',
      scope,
      response_type: 'code',
    }).toString(),
  })

  expect(loginRes.status).toBe(302)
  const location = loginRes.headers.get('location')!
  const code = new URL(location).searchParams.get('code')!
  expect(code).toBeDefined()

  // Exchange code for tokens
  const tokenRes = await server.request('/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: clientId,
      redirect_uri: redirectUri,
      code_verifier: codeVerifier,
    }).toString(),
  })

  expect(tokenRes.status).toBe(200)
  return tokenRes.json()
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test Suite
// ═══════════════════════════════════════════════════════════════════════════════

describe('OAuth Worker Integration Tests', () => {
  let server: OAuth21Server
  let storage: MemoryOAuthStorage

  beforeEach(() => {
    storage = new MemoryOAuthStorage()
    server = createOAuth21Server({
      issuer: 'https://oauth.do',
      storage,
      devMode: {
        enabled: true,
        users: [{ id: 'test-user', email: 'test@example.com', password: 'test123', name: 'Test User' }],
        allowAnyCredentials: true,
      },
      enableDynamicRegistration: true,
      scopes: ['openid', 'profile', 'email', 'offline_access', 'mcp:read', 'mcp:write'],
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // OIDC Discovery
  // ═══════════════════════════════════════════════════════════════════════════

  describe('GET /.well-known/oauth-authorization-server', () => {
    it('returns complete server metadata with all required fields', async () => {
      const res = await server.request('/.well-known/oauth-authorization-server')
      expect(res.status).toBe(200)

      const metadata = await res.json()
      expect(metadata.issuer).toBe('https://oauth.do')
      expect(metadata.authorization_endpoint).toBe('https://oauth.do/authorize')
      expect(metadata.token_endpoint).toBe('https://oauth.do/token')
      expect(metadata.registration_endpoint).toBe('https://oauth.do/register')
      expect(metadata.revocation_endpoint).toBe('https://oauth.do/revoke')
      expect(metadata.introspection_endpoint).toBe('https://oauth.do/introspect')
      expect(metadata.jwks_uri).toBe('https://oauth.do/.well-known/jwks.json')
    })

    it('advertises supported grant types', async () => {
      const res = await server.request('/.well-known/oauth-authorization-server')
      const metadata = await res.json()

      expect(metadata.grant_types_supported).toContain('authorization_code')
      expect(metadata.grant_types_supported).toContain('refresh_token')
    })

    it('advertises S256 as the only supported code challenge method', async () => {
      const res = await server.request('/.well-known/oauth-authorization-server')
      const metadata = await res.json()

      expect(metadata.code_challenge_methods_supported).toEqual(['S256'])
    })

    it('advertises supported scopes', async () => {
      const res = await server.request('/.well-known/oauth-authorization-server')
      const metadata = await res.json()

      expect(metadata.scopes_supported).toContain('openid')
      expect(metadata.scopes_supported).toContain('profile')
      expect(metadata.scopes_supported).toContain('email')
    })

    it('advertises supported token endpoint auth methods', async () => {
      const res = await server.request('/.well-known/oauth-authorization-server')
      const metadata = await res.json()

      expect(metadata.token_endpoint_auth_methods_supported).toContain('none')
      expect(metadata.token_endpoint_auth_methods_supported).toContain('client_secret_basic')
      expect(metadata.token_endpoint_auth_methods_supported).toContain('client_secret_post')
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Dynamic Client Registration (RFC 7591)
  // ═══════════════════════════════════════════════════════════════════════════

  describe('POST /register', () => {
    it('registers a new public client', async () => {
      const res = await server.request('/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_name: 'My Public App',
          redirect_uris: ['https://myapp.com/callback'],
          grant_types: ['authorization_code', 'refresh_token'],
          response_types: ['code'],
          token_endpoint_auth_method: 'none',
        }),
      })

      expect(res.status).toBe(201)
      const client = await res.json()
      expect(client.client_id).toBeDefined()
      expect(client.client_id).toMatch(/^client_/)
      expect(client.client_secret).toBeDefined()
      expect(client.client_name).toBe('My Public App')
      expect(client.redirect_uris).toEqual(['https://myapp.com/callback'])
      expect(client.client_id_issued_at).toBeDefined()
      expect(client.client_secret_expires_at).toBe(0)
    })

    it('registers a confidential client with client_secret', async () => {
      const res = await server.request('/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_name: 'My Server App',
          redirect_uris: ['https://server.app/callback'],
          grant_types: ['authorization_code'],
          response_types: ['code'],
          token_endpoint_auth_method: 'client_secret_post',
        }),
      })

      expect(res.status).toBe(201)
      const client = await res.json()
      expect(client.client_id).toBeDefined()
      expect(client.client_secret).toBeDefined()
      expect(client.token_endpoint_auth_method).toBe('client_secret_post')
    })

    it('rejects registration without redirect_uris', async () => {
      const res = await server.request('/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_name: 'Bad Client',
        }),
      })

      expect(res.status).toBe(400)
      const error = await res.json()
      expect(error.error).toBe('invalid_client_metadata')
      expect(error.error_description).toContain('redirect_uris')
    })

    it('rejects registration without client_name', async () => {
      const res = await server.request('/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          redirect_uris: ['https://example.com/callback'],
        }),
      })

      expect(res.status).toBe(400)
      const error = await res.json()
      expect(error.error).toBe('invalid_client_metadata')
      expect(error.error_description).toContain('client_name')
    })

    it('rejects registration with empty redirect_uris array', async () => {
      const res = await server.request('/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_name: 'No Redirect',
          redirect_uris: [],
        }),
      })

      expect(res.status).toBe(400)
      const error = await res.json()
      expect(error.error).toBe('invalid_client_metadata')
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Authorization Endpoint (GET /authorize)
  // ═══════════════════════════════════════════════════════════════════════════

  describe('GET /authorize', () => {
    let clientId: string

    beforeEach(async () => {
      const client = await registerPublicClient(server)
      clientId = client.client_id
    })

    it('shows login form with valid PKCE authorization request', async () => {
      const codeVerifier = generateCodeVerifier()
      const codeChallenge = await generateCodeChallenge(codeVerifier)

      const res = await server.request(
        `/authorize?response_type=code&client_id=${clientId}&redirect_uri=https://example.com/callback&code_challenge=${codeChallenge}&code_challenge_method=S256&state=test-state&scope=openid+profile`
      )

      expect(res.status).toBe(200)
      const html = await res.text()
      expect(html).toContain('Sign In')
    })

    it('rejects authorization without PKCE code_challenge', async () => {
      const res = await server.request(
        `/authorize?response_type=code&client_id=${clientId}&redirect_uri=https://example.com/callback&state=test`
      )

      // OAuth 2.1: errors redirected to client
      expect(res.status).toBe(302)
      const location = res.headers.get('location')!
      expect(location).toContain('error=invalid_request')
      expect(location).toContain('code_challenge')
    })

    it('rejects plain code challenge method (only S256 allowed)', async () => {
      const res = await server.request(
        `/authorize?response_type=code&client_id=${clientId}&redirect_uri=https://example.com/callback&code_challenge=test&code_challenge_method=plain&state=test`
      )

      expect(res.status).toBe(302)
      const location = res.headers.get('location')!
      expect(location).toContain('error=invalid_request')
      expect(location).toContain('S256')
    })

    it('rejects unknown client_id', async () => {
      const codeChallenge = await generateCodeChallenge(generateCodeVerifier())
      const res = await server.request(
        `/authorize?response_type=code&client_id=unknown-client&redirect_uri=https://example.com/callback&code_challenge=${codeChallenge}&code_challenge_method=S256`
      )

      expect(res.status).toBe(400)
      const error = await res.json()
      expect(error.error).toBe('invalid_client')
    })

    it('rejects mismatched redirect_uri', async () => {
      const codeChallenge = await generateCodeChallenge(generateCodeVerifier())
      const res = await server.request(
        `/authorize?response_type=code&client_id=${clientId}&redirect_uri=https://evil.com/callback&code_challenge=${codeChallenge}&code_challenge_method=S256&state=test`
      )

      expect(res.status).toBe(400)
      const error = await res.json()
      expect(error.error).toBe('invalid_request')
      expect(error.error_description).toContain('redirect_uri')
    })

    it('rejects request without client_id', async () => {
      const res = await server.request('/authorize?response_type=code')

      expect(res.status).toBe(400)
      const error = await res.json()
      expect(error).toHaveProperty('error')
      expect(error).toHaveProperty('error_description')
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // POST /token -- authorization_code grant
  // ═══════════════════════════════════════════════════════════════════════════

  describe('POST /token -- authorization_code grant', () => {
    let clientId: string

    beforeEach(async () => {
      const client = await registerPublicClient(server)
      clientId = client.client_id
    })

    it('exchanges authorization code for tokens with valid PKCE', async () => {
      const codeVerifier = generateCodeVerifier()
      const codeChallenge = await generateCodeChallenge(codeVerifier)

      // Step 1: Login to get auth code
      const loginRes = await server.request('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          email: 'test@example.com',
          password: 'test123',
          client_id: clientId,
          redirect_uri: 'https://example.com/callback',
          code_challenge: codeChallenge,
          code_challenge_method: 'S256',
          state: 'test-state',
          scope: 'openid profile',
          response_type: 'code',
        }).toString(),
      })

      expect(loginRes.status).toBe(302)
      const location = loginRes.headers.get('location')!
      expect(location).toContain('code=')
      expect(location).toContain('state=test-state')
      const code = new URL(location).searchParams.get('code')!

      // Step 2: Exchange code for tokens
      const tokenRes = await server.request('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          client_id: clientId,
          redirect_uri: 'https://example.com/callback',
          code_verifier: codeVerifier,
        }).toString(),
      })

      expect(tokenRes.status).toBe(200)
      const tokens = await tokenRes.json()
      expect(tokens.access_token).toBeDefined()
      expect(tokens.refresh_token).toBeDefined()
      expect(tokens.token_type).toBe('Bearer')
      expect(tokens.expires_in).toBe(3600)
      expect(tokens.scope).toContain('openid')
    })

    it('accepts JSON content type for token request', async () => {
      const codeVerifier = generateCodeVerifier()
      const codeChallenge = await generateCodeChallenge(codeVerifier)

      const loginRes = await server.request('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          email: 'test@example.com',
          password: 'test123',
          client_id: clientId,
          redirect_uri: 'https://example.com/callback',
          code_challenge: codeChallenge,
          code_challenge_method: 'S256',
          state: 'json-test',
          scope: 'openid',
          response_type: 'code',
        }).toString(),
      })

      const code = new URL(loginRes.headers.get('location')!).searchParams.get('code')!

      const tokenRes = await server.request('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          grant_type: 'authorization_code',
          code,
          client_id: clientId,
          redirect_uri: 'https://example.com/callback',
          code_verifier: codeVerifier,
        }),
      })

      expect(tokenRes.status).toBe(200)
      const tokens = await tokenRes.json()
      expect(tokens.access_token).toBeDefined()
    })

    it('rejects wrong code_verifier', async () => {
      const codeVerifier = generateCodeVerifier()
      const codeChallenge = await generateCodeChallenge(codeVerifier)

      const loginRes = await server.request('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          email: 'test@example.com',
          password: 'test123',
          client_id: clientId,
          redirect_uri: 'https://example.com/callback',
          code_challenge: codeChallenge,
          code_challenge_method: 'S256',
          state: 'test',
          scope: 'openid',
          response_type: 'code',
        }).toString(),
      })

      const code = new URL(loginRes.headers.get('location')!).searchParams.get('code')!

      const tokenRes = await server.request('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          client_id: clientId,
          redirect_uri: 'https://example.com/callback',
          code_verifier: 'wrong-verifier-that-does-not-match-the-challenge',
        }).toString(),
      })

      expect(tokenRes.status).toBe(400)
      const error = await tokenRes.json()
      expect(error.error).toBe('invalid_grant')
    })

    it('rejects missing code_verifier', async () => {
      const codeVerifier = generateCodeVerifier()
      const codeChallenge = await generateCodeChallenge(codeVerifier)

      const loginRes = await server.request('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          email: 'test@example.com',
          password: 'test123',
          client_id: clientId,
          redirect_uri: 'https://example.com/callback',
          code_challenge: codeChallenge,
          code_challenge_method: 'S256',
          state: 'test',
          scope: 'openid',
          response_type: 'code',
        }).toString(),
      })

      const code = new URL(loginRes.headers.get('location')!).searchParams.get('code')!

      const tokenRes = await server.request('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          client_id: clientId,
          redirect_uri: 'https://example.com/callback',
          // Missing code_verifier
        }).toString(),
      })

      expect(tokenRes.status).toBe(400)
      const error = await tokenRes.json()
      expect(error.error).toBe('invalid_request')
      expect(error.error_description).toContain('code_verifier')
    })

    it('prevents authorization code reuse (replay attack)', async () => {
      const codeVerifier = generateCodeVerifier()
      const codeChallenge = await generateCodeChallenge(codeVerifier)

      const loginRes = await server.request('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          email: 'test@example.com',
          password: 'test123',
          client_id: clientId,
          redirect_uri: 'https://example.com/callback',
          code_challenge: codeChallenge,
          code_challenge_method: 'S256',
          state: 'test',
          scope: 'openid',
          response_type: 'code',
        }).toString(),
      })

      const code = new URL(loginRes.headers.get('location')!).searchParams.get('code')!

      // First exchange - should succeed
      const firstRes = await server.request('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          client_id: clientId,
          redirect_uri: 'https://example.com/callback',
          code_verifier: codeVerifier,
        }).toString(),
      })
      expect(firstRes.status).toBe(200)

      // Second exchange with same code - should fail
      const secondRes = await server.request('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          client_id: clientId,
          redirect_uri: 'https://example.com/callback',
          code_verifier: codeVerifier,
        }).toString(),
      })
      expect(secondRes.status).toBe(400)
      const error = await secondRes.json()
      expect(error.error).toBe('invalid_grant')
    })

    it('rejects invalid authorization code', async () => {
      const tokenRes = await server.request('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: 'nonexistent-code',
          client_id: clientId,
          redirect_uri: 'https://example.com/callback',
          code_verifier: 'some-verifier',
        }).toString(),
      })

      expect(tokenRes.status).toBe(400)
      const error = await tokenRes.json()
      expect(error.error).toBe('invalid_grant')
    })

    it('rejects expired authorization code', async () => {
      // Directly save an expired auth code via storage
      await storage.saveAuthorizationCode({
        code: 'expired-code-12345',
        clientId,
        userId: 'test-user',
        redirectUri: 'https://example.com/callback',
        scope: 'openid',
        codeChallenge: await generateCodeChallenge(generateCodeVerifier()),
        codeChallengeMethod: 'S256',
        issuedAt: Date.now() - 700000,
        expiresAt: Date.now() - 100000, // Expired
      })

      const tokenRes = await server.request('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: 'expired-code-12345',
          client_id: clientId,
          redirect_uri: 'https://example.com/callback',
          code_verifier: 'any-verifier',
        }).toString(),
      })

      expect(tokenRes.status).toBe(400)
      const error = await tokenRes.json()
      expect(error.error).toBe('invalid_grant')
    })

    it('rejects unsupported grant type', async () => {
      const tokenRes = await server.request('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'password',
          username: 'test',
          password: 'test',
        }).toString(),
      })

      expect(tokenRes.status).toBe(400)
      const error = await tokenRes.json()
      expect(error.error).toBe('unsupported_grant_type')
    })

    it('rejects client_credentials grant type (not supported by this server version)', async () => {
      const tokenRes = await server.request('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
          client_id: clientId,
        }).toString(),
      })

      expect(tokenRes.status).toBe(400)
      const error = await tokenRes.json()
      expect(error.error).toBe('unsupported_grant_type')
    })

    it('confidential client rejects token request without secret', async () => {
      const client = await registerConfidentialClient(server)
      const codeVerifier = generateCodeVerifier()
      const codeChallenge = await generateCodeChallenge(codeVerifier)

      // Get auth code
      const loginRes = await server.request('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          email: 'test@example.com',
          password: 'test123',
          client_id: client.client_id,
          redirect_uri: 'https://confidential.example.com/callback',
          code_challenge: codeChallenge,
          code_challenge_method: 'S256',
          state: 'test',
          scope: 'openid',
          response_type: 'code',
        }).toString(),
      })

      const code = new URL(loginRes.headers.get('location')!).searchParams.get('code')!

      // Try to exchange without client_secret
      const tokenRes = await server.request('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          client_id: client.client_id,
          redirect_uri: 'https://confidential.example.com/callback',
          code_verifier: codeVerifier,
          // Missing client_secret
        }).toString(),
      })

      expect(tokenRes.status).toBe(401)
      const error = await tokenRes.json()
      expect(error.error).toBe('invalid_client')
    })

    it('confidential client rejects token request with wrong secret', async () => {
      const client = await registerConfidentialClient(server)
      const codeVerifier = generateCodeVerifier()
      const codeChallenge = await generateCodeChallenge(codeVerifier)

      const loginRes = await server.request('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          email: 'test@example.com',
          password: 'test123',
          client_id: client.client_id,
          redirect_uri: 'https://confidential.example.com/callback',
          code_challenge: codeChallenge,
          code_challenge_method: 'S256',
          state: 'test',
          scope: 'openid',
          response_type: 'code',
        }).toString(),
      })

      const code = new URL(loginRes.headers.get('location')!).searchParams.get('code')!

      const tokenRes = await server.request('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          client_id: client.client_id,
          client_secret: 'wrong-secret',
          redirect_uri: 'https://confidential.example.com/callback',
          code_verifier: codeVerifier,
        }).toString(),
      })

      expect(tokenRes.status).toBe(401)
      const error = await tokenRes.json()
      expect(error.error).toBe('invalid_client')
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // POST /token -- refresh_token grant
  // ═══════════════════════════════════════════════════════════════════════════

  describe('POST /token -- refresh_token grant', () => {
    let clientId: string

    beforeEach(async () => {
      const client = await registerPublicClient(server)
      clientId = client.client_id
    })

    it('exchanges refresh token for new access token', async () => {
      const tokens = await getTokensViaAuthCodeFlow(server, clientId)

      const refreshRes = await server.request('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: tokens.refresh_token,
          client_id: clientId,
        }).toString(),
      })

      expect(refreshRes.status).toBe(200)
      const newTokens = await refreshRes.json()
      expect(newTokens.access_token).toBeDefined()
      expect(newTokens.access_token).not.toBe(tokens.access_token)
      expect(newTokens.refresh_token).toBeDefined()
      expect(newTokens.refresh_token).not.toBe(tokens.refresh_token) // Rotation
      expect(newTokens.token_type).toBe('Bearer')
      expect(newTokens.expires_in).toBe(3600)
    })

    it('implements refresh token rotation (old token invalidated)', async () => {
      const tokens = await getTokensViaAuthCodeFlow(server, clientId)

      // First refresh - should succeed
      const refreshRes = await server.request('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: tokens.refresh_token,
          client_id: clientId,
        }).toString(),
      })
      expect(refreshRes.status).toBe(200)

      // Use old refresh token again - should fail (revoked during rotation)
      const secondRefreshRes = await server.request('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: tokens.refresh_token,
          client_id: clientId,
        }).toString(),
      })
      expect(secondRefreshRes.status).toBe(400)
      const error = await secondRefreshRes.json()
      expect(error.error).toBe('invalid_grant')
    })

    it('rejects refresh token from a different client', async () => {
      const tokens = await getTokensViaAuthCodeFlow(server, clientId)

      // Register another client
      const otherClient = await registerPublicClient(server, 'Other Client', 'https://other.example.com/callback')

      const refreshRes = await server.request('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: tokens.refresh_token,
          client_id: otherClient.client_id,
        }).toString(),
      })

      expect(refreshRes.status).toBe(400)
      const error = await refreshRes.json()
      expect(error.error).toBe('invalid_grant')
    })

    it('rejects invalid refresh token', async () => {
      const refreshRes = await server.request('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: 'nonexistent-refresh-token',
          client_id: clientId,
        }).toString(),
      })

      expect(refreshRes.status).toBe(400)
      const error = await refreshRes.json()
      expect(error.error).toBe('invalid_grant')
    })

    it('rejects missing refresh_token parameter', async () => {
      const refreshRes = await server.request('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          client_id: clientId,
        }).toString(),
      })

      expect(refreshRes.status).toBe(400)
      const error = await refreshRes.json()
      expect(error.error).toBe('invalid_request')
      expect(error.error_description).toContain('refresh_token')
    })

    it('rejects revoked refresh token', async () => {
      const tokens = await getTokensViaAuthCodeFlow(server, clientId)

      // Manually revoke the refresh token
      await storage.revokeRefreshToken(tokens.refresh_token)

      const refreshRes = await server.request('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: tokens.refresh_token,
          client_id: clientId,
        }).toString(),
      })

      expect(refreshRes.status).toBe(400)
      const error = await refreshRes.json()
      expect(error.error).toBe('invalid_grant')
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // POST /introspect -- Token Introspection (RFC 7662)
  // ═══════════════════════════════════════════════════════════════════════════

  describe('POST /introspect', () => {
    let clientId: string

    beforeEach(async () => {
      const client = await registerPublicClient(server)
      clientId = client.client_id
    })

    it('returns active=true for valid opaque access token', async () => {
      const tokens = await getTokensViaAuthCodeFlow(server, clientId)

      const introspectRes = await server.request('/introspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: tokens.access_token }).toString(),
      })

      expect(introspectRes.status).toBe(200)
      const data = await introspectRes.json()
      expect(data.active).toBe(true)
      expect(data.sub).toBe('test-user')
      expect(data.client_id).toBe(clientId)
      expect(data.token_type).toBe('Bearer')
      expect(data.exp).toBeDefined()
      expect(data.iat).toBeDefined()
    })

    it('returns active=false for revoked token', async () => {
      const tokens = await getTokensViaAuthCodeFlow(server, clientId)

      // Revoke it
      await storage.revokeAccessToken(tokens.access_token)

      const introspectRes = await server.request('/introspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: tokens.access_token }).toString(),
      })

      expect(introspectRes.status).toBe(200)
      const data = await introspectRes.json()
      expect(data.active).toBe(false)
    })

    it('returns active=false for expired token', async () => {
      // Create an expired token directly
      await storage.saveAccessToken({
        token: 'expired-access-token',
        tokenType: 'Bearer',
        clientId,
        userId: 'test-user',
        scope: 'openid',
        issuedAt: Date.now() - 7200000,
        expiresAt: Date.now() - 3600000, // Expired 1 hour ago
      })

      const introspectRes = await server.request('/introspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: 'expired-access-token' }).toString(),
      })

      expect(introspectRes.status).toBe(200)
      const data = await introspectRes.json()
      expect(data.active).toBe(false)
    })

    it('returns active=false for nonexistent token', async () => {
      const introspectRes = await server.request('/introspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: 'nonexistent-token' }).toString(),
      })

      expect(introspectRes.status).toBe(200)
      const data = await introspectRes.json()
      expect(data.active).toBe(false)
    })

    it('returns active=false when token parameter is missing', async () => {
      const introspectRes = await server.request('/introspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({}).toString(),
      })

      expect(introspectRes.status).toBe(200)
      const data = await introspectRes.json()
      expect(data.active).toBe(false)
    })

    it('accepts JSON content type', async () => {
      const tokens = await getTokensViaAuthCodeFlow(server, clientId)

      const introspectRes = await server.request('/introspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: tokens.access_token }),
      })

      expect(introspectRes.status).toBe(200)
      const data = await introspectRes.json()
      expect(data.active).toBe(true)
    })

    it('returns correct scope for introspected token', async () => {
      const tokens = await getTokensViaAuthCodeFlow(server, clientId, 'https://example.com/callback', 'openid profile')

      const introspectRes = await server.request('/introspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: tokens.access_token }).toString(),
      })

      const data = await introspectRes.json()
      expect(data.active).toBe(true)
      expect(data.scope).toContain('openid')
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // POST /revoke -- Token Revocation (RFC 7009)
  // ═══════════════════════════════════════════════════════════════════════════

  describe('POST /revoke', () => {
    let clientId: string

    beforeEach(async () => {
      const client = await registerPublicClient(server)
      clientId = client.client_id
    })

    it('revokes an access token', async () => {
      const tokens = await getTokensViaAuthCodeFlow(server, clientId)

      const revokeRes = await server.request('/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          token: tokens.access_token,
        }).toString(),
      })

      expect(revokeRes.status).toBe(200)

      // Verify token is no longer valid
      const storedToken = await storage.getAccessToken(tokens.access_token)
      expect(storedToken).toBeNull()
    })

    it('revokes a refresh token', async () => {
      const tokens = await getTokensViaAuthCodeFlow(server, clientId)

      const revokeRes = await server.request('/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          token: tokens.refresh_token,
          token_type_hint: 'refresh_token',
        }).toString(),
      })

      expect(revokeRes.status).toBe(200)

      // Verify refresh token is revoked
      const storedToken = await storage.getRefreshToken(tokens.refresh_token)
      expect(storedToken?.revoked).toBe(true)
    })

    it('returns 200 even for unknown tokens (RFC 7009 requirement)', async () => {
      const revokeRes = await server.request('/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          token: 'nonexistent-token-that-never-existed',
        }).toString(),
      })

      expect(revokeRes.status).toBe(200)
    })

    it('rejects revocation without token parameter', async () => {
      const revokeRes = await server.request('/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({}).toString(),
      })

      expect(revokeRes.status).toBe(400)
      const error = await revokeRes.json()
      expect(error.error).toBe('invalid_request')
      expect(error.error_description).toContain('token')
    })

    it('revoked access token fails introspection', async () => {
      const tokens = await getTokensViaAuthCodeFlow(server, clientId)

      // Revoke
      await server.request('/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: tokens.access_token }).toString(),
      })

      // Introspect - should be inactive
      const introspectRes = await server.request('/introspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: tokens.access_token }).toString(),
      })

      expect(introspectRes.status).toBe(200)
      const data = await introspectRes.json()
      expect(data.active).toBe(false)
    })

    it('revoked refresh token cannot be used for token refresh', async () => {
      const tokens = await getTokensViaAuthCodeFlow(server, clientId)

      // Revoke the refresh token
      await server.request('/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          token: tokens.refresh_token,
          token_type_hint: 'refresh_token',
        }).toString(),
      })

      // Try to use the revoked refresh token
      const refreshRes = await server.request('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: tokens.refresh_token,
          client_id: clientId,
        }).toString(),
      })

      expect(refreshRes.status).toBe(400)
      const error = await refreshRes.json()
      expect(error.error).toBe('invalid_grant')
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // End-to-end: Full OAuth 2.1 lifecycle
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Full OAuth 2.1 lifecycle', () => {
    it('register -> authorize -> token -> introspect -> refresh -> revoke', async () => {
      // 1. Register client
      const client = await registerPublicClient(server, 'Lifecycle Client')

      // 2. Get tokens via auth code flow
      const tokens = await getTokensViaAuthCodeFlow(server, client.client_id)
      expect(tokens.access_token).toBeDefined()
      expect(tokens.refresh_token).toBeDefined()

      // 3. Introspect access token
      const introspectRes = await server.request('/introspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: tokens.access_token }).toString(),
      })
      const introspectData = await introspectRes.json()
      expect(introspectData.active).toBe(true)
      expect(introspectData.sub).toBe('test-user')

      // 4. Refresh token
      const refreshRes = await server.request('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: tokens.refresh_token,
          client_id: client.client_id,
        }).toString(),
      })
      expect(refreshRes.status).toBe(200)
      const newTokens = await refreshRes.json()
      expect(newTokens.access_token).toBeDefined()

      // 5. Introspect new access token
      const newIntrospectRes = await server.request('/introspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: newTokens.access_token }).toString(),
      })
      const newIntrospectData = await newIntrospectRes.json()
      expect(newIntrospectData.active).toBe(true)

      // 6. Revoke new access token
      const revokeRes = await server.request('/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: newTokens.access_token }).toString(),
      })
      expect(revokeRes.status).toBe(200)

      // 7. Verify revoked token is inactive
      const finalIntrospectRes = await server.request('/introspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: newTokens.access_token }).toString(),
      })
      const finalData = await finalIntrospectRes.json()
      expect(finalData.active).toBe(false)
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Protected Resource Metadata
  // ═══════════════════════════════════════════════════════════════════════════

  describe('GET /.well-known/oauth-protected-resource', () => {
    it('returns protected resource metadata', async () => {
      const res = await server.request('/.well-known/oauth-protected-resource')
      expect(res.status).toBe(200)

      const metadata = await res.json()
      expect(metadata.resource).toBe('https://oauth.do')
      expect(metadata.authorization_servers).toContain('https://oauth.do')
      expect(metadata.bearer_methods_supported).toContain('header')
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // JWKS Endpoint
  // ═══════════════════════════════════════════════════════════════════════════

  describe('GET /.well-known/jwks.json', () => {
    it('returns empty keys when no signing key manager configured', async () => {
      const res = await server.request('/.well-known/jwks.json')
      expect(res.status).toBe(200)

      const jwks = await res.json()
      expect(jwks.keys).toEqual([])
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Error Cases
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Error cases', () => {
    it('returns proper OAuth error format for all error responses', async () => {
      const res = await server.request('/authorize?response_type=code')
      expect(res.status).toBe(400)

      const error = await res.json()
      expect(error).toHaveProperty('error')
      expect(error).toHaveProperty('error_description')
      expect(typeof error.error).toBe('string')
      expect(typeof error.error_description).toBe('string')
    })

    it('rejects token request without grant_type', async () => {
      const res = await server.request('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: 'some-client',
        }).toString(),
      })

      expect(res.status).toBe(400)
      const error = await res.json()
      expect(error.error).toBe('unsupported_grant_type')
    })

    it('rejects token request with missing code in authorization_code grant', async () => {
      const client = await registerPublicClient(server)

      const res = await server.request('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: client.client_id,
          redirect_uri: 'https://example.com/callback',
          code_verifier: 'some-verifier',
          // Missing code
        }).toString(),
      })

      expect(res.status).toBe(400)
      const error = await res.json()
      expect(error.error).toBe('invalid_request')
    })

    it('rejects token request with missing client_id', async () => {
      const res = await server.request('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: 'some-code',
          redirect_uri: 'https://example.com/callback',
          code_verifier: 'some-verifier',
        }).toString(),
      })

      expect(res.status).toBe(400)
      const error = await res.json()
      expect(error.error).toBe('invalid_request')
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Test Isolation
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Test isolation', () => {
    it('each test gets fresh storage (no cross-test leakage)', async () => {
      // Register a client
      const client = await registerPublicClient(server, 'Isolated Client')

      // Verify client exists in this test's storage
      const storedClient = await storage.getClient(client.client_id)
      expect(storedClient).not.toBeNull()

      // Verify no leftover clients from other tests
      const clients = await storage.listClients()
      expect(clients.length).toBe(1)
    })

    it('multiple clients can coexist', async () => {
      const client1 = await registerPublicClient(server, 'Client 1', 'https://one.example.com/callback')
      const client2 = await registerPublicClient(server, 'Client 2', 'https://two.example.com/callback')
      const client3 = await registerConfidentialClient(server, 'Client 3', 'https://three.example.com/callback')

      // All three should be retrievable
      expect(await storage.getClient(client1.client_id)).not.toBeNull()
      expect(await storage.getClient(client2.client_id)).not.toBeNull()
      expect(await storage.getClient(client3.client_id)).not.toBeNull()

      const clients = await storage.listClients()
      expect(clients.length).toBe(3)
    })
  })
})
