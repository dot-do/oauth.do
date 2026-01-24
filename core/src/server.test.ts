import { describe, it, expect, beforeEach } from 'vitest'
import { createOAuth21Server, MemoryOAuthStorage, generateCodeChallenge, generateCodeVerifier } from './index'

describe('OAuth 2.1 Server E2E Flow', () => {
  let server: ReturnType<typeof createOAuth21Server>
  let storage: MemoryOAuthStorage

  beforeEach(async () => {
    storage = new MemoryOAuthStorage()
    server = createOAuth21Server({
      issuer: 'https://test.mcp.do',
      storage,
      devMode: {
        enabled: true,
        users: [
          { id: 'test-user', email: 'test@example.com', password: 'test123', name: 'Test User' }
        ],
        allowAnyCredentials: true
      },
      enableDynamicRegistration: true,
      scopes: ['openid', 'profile', 'email', 'mcp:read', 'mcp:write']
    })
  })

  describe('Discovery Endpoints', () => {
    it('serves OAuth authorization server metadata', async () => {
      const response = await server.request('/.well-known/oauth-authorization-server')
      expect(response.status).toBe(200)

      const metadata = await response.json()
      expect(metadata.issuer).toBe('https://test.mcp.do')
      expect(metadata.authorization_endpoint).toBe('https://test.mcp.do/authorize')
      expect(metadata.token_endpoint).toBe('https://test.mcp.do/token')
      expect(metadata.registration_endpoint).toBe('https://test.mcp.do/register')
      expect(metadata.code_challenge_methods_supported).toContain('S256')
      expect(metadata.grant_types_supported).toContain('authorization_code')
      expect(metadata.grant_types_supported).toContain('refresh_token')
    })

    it('serves protected resource metadata', async () => {
      const response = await server.request('/.well-known/oauth-protected-resource')
      expect(response.status).toBe(200)

      const metadata = await response.json()
      expect(metadata.resource).toBe('https://test.mcp.do')
      expect(metadata.authorization_servers).toContain('https://test.mcp.do')
    })
  })

  describe('Dynamic Client Registration (RFC 7591)', () => {
    it('registers a new client', async () => {
      const response = await server.request('/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_name: 'Test Client',
          redirect_uris: ['https://example.com/callback'],
          grant_types: ['authorization_code', 'refresh_token'],
          response_types: ['code'],
          token_endpoint_auth_method: 'none'
        })
      })

      expect(response.status).toBe(201)
      const client = await response.json()
      expect(client.client_id).toBeDefined()
      expect(client.client_name).toBe('Test Client')
      expect(client.redirect_uris).toContain('https://example.com/callback')
    })

    it('rejects registration without redirect_uris', async () => {
      const response = await server.request('/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_name: 'Bad Client'
        })
      })

      expect(response.status).toBe(400)
      const error = await response.json()
      expect(error.error).toBe('invalid_client_metadata')
    })
  })

  describe('Full OAuth 2.1 Authorization Code Flow with PKCE', () => {
    let clientId: string
    let codeVerifier: string
    let codeChallenge: string

    beforeEach(async () => {
      // Register a client
      const regResponse = await server.request('/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_name: 'E2E Test Client',
          redirect_uris: ['https://example.com/callback'],
          grant_types: ['authorization_code', 'refresh_token'],
          response_types: ['code'],
          token_endpoint_auth_method: 'none'
        })
      })
      const client = await regResponse.json()
      clientId = client.client_id

      // Generate PKCE pair
      codeVerifier = generateCodeVerifier()
      codeChallenge = await generateCodeChallenge(codeVerifier)
    })

    it('completes full authorization code flow', async () => {
      // Step 1: Start authorization - should show login form in devMode
      const authUrl = `/authorize?response_type=code&client_id=${clientId}&redirect_uri=https://example.com/callback&code_challenge=${codeChallenge}&code_challenge_method=S256&state=test-state&scope=openid+profile`

      const authResponse = await server.request(authUrl)
      expect(authResponse.status).toBe(200)
      const authHtml = await authResponse.text()
      expect(authHtml).toContain('Sign In')

      // Step 2: Submit login form
      const loginResponse = await server.request('/login', {
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
          response_type: 'code'
        }).toString()
      })

      expect(loginResponse.status).toBe(302)
      const location = loginResponse.headers.get('location')!
      expect(location).toContain('https://example.com/callback')
      expect(location).toContain('code=')
      expect(location).toContain('state=test-state')

      // Extract authorization code
      const code = new URL(location).searchParams.get('code')!
      expect(code).toBeDefined()

      // Step 3: Exchange code for tokens
      const tokenResponse = await server.request('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          client_id: clientId,
          redirect_uri: 'https://example.com/callback',
          code_verifier: codeVerifier
        }).toString()
      })

      expect(tokenResponse.status).toBe(200)
      const tokens = await tokenResponse.json()
      expect(tokens.access_token).toBeDefined()
      expect(tokens.refresh_token).toBeDefined()
      expect(tokens.token_type).toBe('Bearer')
      expect(tokens.expires_in).toBe(3600)
      expect(tokens.scope).toContain('openid')

      // Step 4: Use refresh token to get new access token
      const refreshResponse = await server.request('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: tokens.refresh_token,
          client_id: clientId
        }).toString()
      })

      expect(refreshResponse.status).toBe(200)
      const newTokens = await refreshResponse.json()
      expect(newTokens.access_token).toBeDefined()
      expect(newTokens.access_token).not.toBe(tokens.access_token)
    })

    it('rejects authorization without PKCE', async () => {
      // OAuth 2.1 spec: errors are returned via redirect to client's redirect_uri
      const response = await server.request(
        `/authorize?response_type=code&client_id=${clientId}&redirect_uri=https://example.com/callback&state=test`
      )

      expect(response.status).toBe(302)
      const location = response.headers.get('location')!
      expect(location).toContain('error=invalid_request')
      expect(location).toContain('code_challenge')
    })

    it('rejects plain code challenge method', async () => {
      // OAuth 2.1 spec: errors are returned via redirect to client's redirect_uri
      const response = await server.request(
        `/authorize?response_type=code&client_id=${clientId}&redirect_uri=https://example.com/callback&code_challenge=test&code_challenge_method=plain&state=test`
      )

      expect(response.status).toBe(302)
      const location = response.headers.get('location')!
      expect(location).toContain('error=invalid_request')
      expect(location).toContain('S256')
    })

    it('rejects token exchange with wrong code_verifier', async () => {
      // Get auth code first
      const loginResponse = await server.request('/login', {
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
          response_type: 'code'
        }).toString()
      })

      const location = loginResponse.headers.get('location')!
      const code = new URL(location).searchParams.get('code')!

      // Try to exchange with wrong verifier
      const tokenResponse = await server.request('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          client_id: clientId,
          redirect_uri: 'https://example.com/callback',
          code_verifier: 'wrong-verifier-that-does-not-match'
        }).toString()
      })

      expect(tokenResponse.status).toBe(400)
      const error = await tokenResponse.json()
      expect(error.error).toBe('invalid_grant')
    })

    it('prevents authorization code reuse', async () => {
      // Get auth code
      const loginResponse = await server.request('/login', {
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
          response_type: 'code'
        }).toString()
      })

      const location = loginResponse.headers.get('location')!
      const code = new URL(location).searchParams.get('code')!

      // First exchange - should succeed
      const firstResponse = await server.request('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          client_id: clientId,
          redirect_uri: 'https://example.com/callback',
          code_verifier: codeVerifier
        }).toString()
      })
      expect(firstResponse.status).toBe(200)

      // Second exchange with same code - should fail
      const secondResponse = await server.request('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          client_id: clientId,
          redirect_uri: 'https://example.com/callback',
          code_verifier: codeVerifier
        }).toString()
      })

      expect(secondResponse.status).toBe(400)
      const error = await secondResponse.json()
      expect(error.error).toBe('invalid_grant')
    })
  })

  describe('Token Revocation (RFC 7009)', () => {
    it('revokes access token', async () => {
      // Create a token via test helpers
      await server.testHelpers!.createUser({ id: 'revoke-user', email: 'revoke@example.com' })
      const tokens = await server.testHelpers!.getAccessToken('revoke-user', 'test-client', 'openid')

      // Revoke the token
      const revokeResponse = await server.request('/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          token: tokens.accessToken,
          client_id: 'test-client'
        }).toString()
      })

      expect(revokeResponse.status).toBe(200)

      // Verify token is no longer valid in storage
      const storedToken = await storage.getAccessToken(tokens.accessToken)
      expect(storedToken).toBeNull()
    })

    it('revokes refresh token', async () => {
      await server.testHelpers!.createUser({ id: 'revoke-user2', email: 'revoke2@example.com' })
      const tokens = await server.testHelpers!.getAccessToken('revoke-user2', 'test-client', 'openid')

      const revokeResponse = await server.request('/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          token: tokens.refreshToken,
          token_type_hint: 'refresh_token',
          client_id: 'test-client'
        }).toString()
      })

      expect(revokeResponse.status).toBe(200)

      // Verify refresh token is marked as revoked (implementation marks revoked rather than deleting)
      const storedToken = await storage.getRefreshToken(tokens.refreshToken)
      expect(storedToken?.revoked).toBe(true)
    })
  })

  describe('Test Helpers', () => {
    it('creates access tokens programmatically', async () => {
      await server.testHelpers!.createUser({ id: 'helper-user', email: 'helper@example.com' })
      const tokens = await server.testHelpers!.getAccessToken('helper-user', 'test-client', 'openid profile')

      expect(tokens.accessToken).toBeDefined()
      expect(tokens.refreshToken).toBeDefined()
      expect(tokens.expiresIn).toBe(3600)

      // Verify token exists in storage
      const stored = await storage.getAccessToken(tokens.accessToken)
      expect(stored).not.toBeNull()
      expect(stored?.userId).toBe('helper-user')
    })

    it('creates authorization codes programmatically', async () => {
      const code = await server.testHelpers!.createAuthorizationCode({
        clientId: 'test-client',
        userId: 'test-user',
        redirectUri: 'https://example.com/callback',
        scope: 'openid',
        codeChallenge: 'test-challenge'
      })

      expect(code).toBeDefined()
      expect(code.length).toBeGreaterThan(32)
    })

    it('generates session cookies for Playwright', async () => {
      await server.testHelpers!.createUser({ id: 'cookie-user', email: 'cookie@example.com' })
      const cookies = await server.testHelpers!.getSessionCookies('cookie-user')

      expect(cookies).toHaveLength(1)
      expect(cookies[0].name).toBe('oauth_access_token')
      expect(cookies[0].httpOnly).toBe(true)
      expect(cookies[0].secure).toBe(true)
      expect(cookies[0].sameSite).toBe('Lax')
    })
  })

  describe('Error Handling', () => {
    it('returns proper OAuth error format', async () => {
      const response = await server.request('/authorize?response_type=code')

      expect(response.status).toBe(400)
      const error = await response.json()
      expect(error).toHaveProperty('error')
      expect(error).toHaveProperty('error_description')
    })

    it('rejects unknown client', async () => {
      const response = await server.request(
        '/authorize?response_type=code&client_id=unknown&redirect_uri=https://example.com/callback&code_challenge=test&code_challenge_method=S256'
      )

      expect(response.status).toBe(400)
      const error = await response.json()
      expect(error.error).toBe('invalid_client')
    })

    it('rejects mismatched redirect_uri', async () => {
      // Register client with specific redirect_uri
      const regResponse = await server.request('/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_name: 'Redirect Test',
          redirect_uris: ['https://allowed.com/callback'],
          grant_types: ['authorization_code'],
          response_types: ['code'],
          token_endpoint_auth_method: 'none'
        })
      })
      const client = await regResponse.json()

      // Try to authorize with different redirect_uri
      const response = await server.request(
        `/authorize?response_type=code&client_id=${client.client_id}&redirect_uri=https://evil.com/callback&code_challenge=test&code_challenge_method=S256`
      )

      expect(response.status).toBe(400)
      const error = await response.json()
      expect(error.error).toBe('invalid_request')
      expect(error.error_description).toContain('redirect_uri')
    })
  })
})
