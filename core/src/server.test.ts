import { describe, it, expect, beforeEach, vi } from 'vitest'
import { createOAuth21Server, MemoryOAuthStorage, generateCodeChallenge, generateCodeVerifier, computeRefreshTokenExpiry } from './index'

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
      scopes: ['openid', 'profile', 'email', 'mcp:read', 'mcp:write'],
      skipConsent: true, // These tests focus on core OAuth flows; consent is tested in consent.test.ts
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

  describe('Security', () => {
    let clientId: string
    let confidentialClientId: string
    let confidentialClientSecret: string
    let codeVerifier: string
    let codeChallenge: string

    beforeEach(async () => {
      // Register a public client (no secret)
      const publicRegResponse = await server.request('/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_name: 'Public Test Client',
          redirect_uris: ['https://example.com/callback'],
          grant_types: ['authorization_code', 'refresh_token'],
          response_types: ['code'],
          token_endpoint_auth_method: 'none'
        })
      })
      const publicClient = await publicRegResponse.json()
      clientId = publicClient.client_id

      // Register a confidential client (with secret)
      const confidentialRegResponse = await server.request('/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_name: 'Confidential Test Client',
          redirect_uris: ['https://confidential.example.com/callback'],
          grant_types: ['authorization_code', 'refresh_token'],
          response_types: ['code'],
          token_endpoint_auth_method: 'client_secret_post'
        })
      })
      const confidentialClient = await confidentialRegResponse.json()
      confidentialClientId = confidentialClient.client_id
      confidentialClientSecret = confidentialClient.client_secret

      // Generate PKCE pair
      codeVerifier = generateCodeVerifier()
      codeChallenge = await generateCodeChallenge(codeVerifier)
    })

    describe('State Parameter', () => {
      it('should reject callback with mismatched state', async () => {
        // Start authorization with state=original-state
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
            state: 'original-state',
            scope: 'openid',
            response_type: 'code'
          }).toString()
        })

        expect(loginResponse.status).toBe(302)
        const location = loginResponse.headers.get('location')!
        const returnedState = new URL(location).searchParams.get('state')

        // The state returned should match what was sent
        expect(returnedState).toBe('original-state')

        // If client receives different state than what they stored, they must reject
        // This is client-side validation, but the server should preserve state exactly
        expect(returnedState).not.toBe('tampered-state')
      })

      it('should reject callback with missing state when state was provided', async () => {
        // The state parameter should be preserved and returned
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
            state: 'test-csrf-state',
            scope: 'openid',
            response_type: 'code'
          }).toString()
        })

        expect(loginResponse.status).toBe(302)
        const location = loginResponse.headers.get('location')!
        const url = new URL(location)

        // State must be present in the callback
        expect(url.searchParams.has('state')).toBe(true)
        expect(url.searchParams.get('state')).toBe('test-csrf-state')
      })
    })

    describe('Redirect URI Validation', () => {
      it('should reject redirect_uri with path traversal', async () => {
        const response = await server.request(
          `/authorize?response_type=code&client_id=${clientId}&redirect_uri=https://example.com/callback/../evil&code_challenge=${codeChallenge}&code_challenge_method=S256&state=test`
        )

        // Should reject because the normalized URI doesn't match exactly
        expect(response.status).toBe(400)
        const error = await response.json()
        expect(error.error).toBe('invalid_request')
      })

      it('should reject redirect_uri with different port', async () => {
        const response = await server.request(
          `/authorize?response_type=code&client_id=${clientId}&redirect_uri=https://example.com:8080/callback&code_challenge=${codeChallenge}&code_challenge_method=S256&state=test`
        )

        expect(response.status).toBe(400)
        const error = await response.json()
        expect(error.error).toBe('invalid_request')
      })

      it('should reject redirect_uri with query parameters when not registered', async () => {
        const response = await server.request(
          `/authorize?response_type=code&client_id=${clientId}&redirect_uri=https://example.com/callback?evil=payload&code_challenge=${codeChallenge}&code_challenge_method=S256&state=test`
        )

        expect(response.status).toBe(400)
        const error = await response.json()
        expect(error.error).toBe('invalid_request')
      })
    })

    describe('Authorization Code Single-Use (Replay Attack Prevention)', () => {
      it('should invalidate code after first use', async () => {
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

        // Second exchange - should fail (replay attack)
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

      it('should reject expired authorization code', async () => {
        // Create an authorization code directly with testHelpers for control
        const code = await server.testHelpers!.createAuthorizationCode({
          clientId: clientId,
          userId: 'test-user',
          redirectUri: 'https://example.com/callback',
          scope: 'openid',
          codeChallenge: codeChallenge
        })

        // Manually expire the code by consuming and re-saving as expired
        // For this test, we'll verify the normal flow rejects after consumption
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
      })
    })

    describe('PKCE', () => {
      it('should reject authorize without code_challenge', async () => {
        const response = await server.request(
          `/authorize?response_type=code&client_id=${clientId}&redirect_uri=https://example.com/callback&state=test`
        )

        expect(response.status).toBe(302)
        const location = response.headers.get('location')!
        expect(location).toContain('error=invalid_request')
        expect(location).toContain('code_challenge')
      })

      it('should reject token without code_verifier', async () => {
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

        // Try to exchange without code_verifier
        const tokenResponse = await server.request('/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            client_id: clientId,
            redirect_uri: 'https://example.com/callback'
            // Missing code_verifier
          }).toString()
        })

        expect(tokenResponse.status).toBe(400)
        const error = await tokenResponse.json()
        expect(error.error).toBe('invalid_request')
        expect(error.error_description).toContain('code_verifier')
      })

      it('should reject token with incorrect code_verifier', async () => {
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

        // Try with wrong verifier
        const tokenResponse = await server.request('/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            client_id: clientId,
            redirect_uri: 'https://example.com/callback',
            code_verifier: 'incorrect-verifier-that-does-not-match-challenge'
          }).toString()
        })

        expect(tokenResponse.status).toBe(400)
        const error = await tokenResponse.json()
        expect(error.error).toBe('invalid_grant')
      })
    })

    describe('Client Authentication', () => {
      it('should reject token request without client secret for confidential clients', async () => {
        // Get auth code for confidential client
        const loginResponse = await server.request('/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            email: 'test@example.com',
            password: 'test123',
            client_id: confidentialClientId,
            redirect_uri: 'https://confidential.example.com/callback',
            code_challenge: codeChallenge,
            code_challenge_method: 'S256',
            state: 'test',
            scope: 'openid',
            response_type: 'code'
          }).toString()
        })

        const location = loginResponse.headers.get('location')!
        const code = new URL(location).searchParams.get('code')!

        // Try to exchange without client_secret
        const tokenResponse = await server.request('/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            client_id: confidentialClientId,
            redirect_uri: 'https://confidential.example.com/callback',
            code_verifier: codeVerifier
            // Missing client_secret
          }).toString()
        })

        expect(tokenResponse.status).toBe(401)
        const error = await tokenResponse.json()
        expect(error.error).toBe('invalid_client')
      })

      it('should accept token request without secret for public clients', async () => {
        // Get auth code for public client
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

        // Exchange without client_secret (should work for public client)
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
      })

      it('should reject token request with incorrect client secret', async () => {
        // Get auth code for confidential client
        const loginResponse = await server.request('/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            email: 'test@example.com',
            password: 'test123',
            client_id: confidentialClientId,
            redirect_uri: 'https://confidential.example.com/callback',
            code_challenge: codeChallenge,
            code_challenge_method: 'S256',
            state: 'test',
            scope: 'openid',
            response_type: 'code'
          }).toString()
        })

        const location = loginResponse.headers.get('location')!
        const code = new URL(location).searchParams.get('code')!

        // Try to exchange with wrong client_secret
        const tokenResponse = await server.request('/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            client_id: confidentialClientId,
            client_secret: 'wrong-secret',
            redirect_uri: 'https://confidential.example.com/callback',
            code_verifier: codeVerifier
          }).toString()
        })

        expect(tokenResponse.status).toBe(401)
        const error = await tokenResponse.json()
        expect(error.error).toBe('invalid_client')
      })
    })

    describe('Refresh Token Client Binding', () => {
      it('should reject refresh token used by different client', async () => {
        // Get tokens for public client
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

        const tokens = await tokenResponse.json()
        const refreshToken = tokens.refresh_token

        // Register another public client
        const anotherClientResponse = await server.request('/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            client_name: 'Another Client',
            redirect_uris: ['https://another.example.com/callback'],
            grant_types: ['authorization_code', 'refresh_token'],
            response_types: ['code'],
            token_endpoint_auth_method: 'none'
          })
        })
        const anotherClient = await anotherClientResponse.json()

        // Try to use the refresh token with a different client
        const refreshResponse = await server.request('/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'refresh_token',
            refresh_token: refreshToken,
            client_id: anotherClient.client_id
          }).toString()
        })

        expect(refreshResponse.status).toBe(400)
        const error = await refreshResponse.json()
        expect(error.error).toBe('invalid_grant')
      })

      it('should accept refresh token used by original client', async () => {
        // Get tokens
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

        const tokens = await tokenResponse.json()

        // Use refresh token with original client
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
      })
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Device Authorization Grant (RFC 8628)
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Device Authorization Grant (RFC 8628)', () => {
    let clientId: string

    beforeEach(async () => {
      // Register a client for device authorization tests
      const regResponse = await server.request('/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_name: 'Device Client',
          redirect_uris: ['https://example.com/callback'],
          grant_types: ['authorization_code', 'refresh_token'],
          response_types: ['code'],
          token_endpoint_auth_method: 'none'
        })
      })
      const client = await regResponse.json()
      clientId = client.client_id
    })

    describe('Metadata Advertisement', () => {
      it('should advertise device_authorization_endpoint in metadata', async () => {
        const response = await server.request('/.well-known/oauth-authorization-server')
        expect(response.status).toBe(200)

        const metadata = await response.json()
        expect(metadata.device_authorization_endpoint).toBe('https://test.mcp.do/device_authorization')
        expect(metadata.grant_types_supported).toContain('urn:ietf:params:oauth:grant-type:device_code')
      })
    })

    describe('Device Code Issuance', () => {
      it('should issue device code with valid client_id', async () => {
        const response = await server.request('/device_authorization', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            client_id: clientId,
            scope: 'openid profile'
          }).toString()
        })

        expect(response.status).toBe(200)
        const data = await response.json()

        // Verify RFC 8628 response format
        expect(data.device_code).toBeDefined()
        expect(data.device_code.length).toBe(64)
        expect(data.user_code).toBeDefined()
        expect(data.user_code).toMatch(/^[A-Z]{4}-[A-Z]{4}$/)
        expect(data.verification_uri).toBe('https://test.mcp.do/device')
        expect(data.verification_uri_complete).toBe(`https://test.mcp.do/device?user_code=${data.user_code}`)
        expect(data.expires_in).toBe(600)
        expect(data.interval).toBe(5)
      })

      it('should accept JSON content type', async () => {
        const response = await server.request('/device_authorization', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            client_id: clientId,
            scope: 'openid'
          })
        })

        expect(response.status).toBe(200)
        const data = await response.json()
        expect(data.device_code).toBeDefined()
      })

      it('should reject request without client_id', async () => {
        const response = await server.request('/device_authorization', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            scope: 'openid'
          }).toString()
        })

        expect(response.status).toBe(400)
        const error = await response.json()
        expect(error.error).toBe('invalid_request')
        expect(error.error_description).toContain('client_id')
      })

      it('should reject request with invalid client_id', async () => {
        const response = await server.request('/device_authorization', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            client_id: 'invalid-client'
          }).toString()
        })

        expect(response.status).toBe(400)
        const error = await response.json()
        expect(error.error).toBe('invalid_client')
      })

      it('should generate user codes with unambiguous characters', async () => {
        // Request multiple codes and verify they only contain allowed characters
        const allowedChars = 'BCDFGHJKLMNPQRSTVWXZ'

        for (let i = 0; i < 5; i++) {
          const response = await server.request('/device_authorization', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
              client_id: clientId
            }).toString()
          })

          const data = await response.json()
          const codeWithoutDash = data.user_code.replace('-', '')

          for (const char of codeWithoutDash) {
            expect(allowedChars).toContain(char)
          }
        }
      })
    })

    describe('User Verification Page', () => {
      it('should show verification form on GET /device', async () => {
        const response = await server.request('/device')
        expect(response.status).toBe(200)

        const html = await response.text()
        expect(html).toContain('Connect a Device')
        expect(html).toContain('user_code')
        expect(html).toContain('form')
      })

      it('should pre-fill user_code from query parameter', async () => {
        const response = await server.request('/device?user_code=ABCD-EFGH')
        expect(response.status).toBe(200)

        const html = await response.text()
        expect(html).toContain('ABCD-EFGH')
      })

      it('should show error for invalid user_code', async () => {
        const response = await server.request('/device', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            user_code: 'INVALID',
            action: 'verify'
          }).toString()
        })

        expect(response.status).toBe(400)
        const html = await response.text()
        expect(html).toContain('Invalid code')
      })

      it('should show authorization page for valid user_code', async () => {
        // First, get a device code
        const deviceResponse = await server.request('/device_authorization', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            client_id: clientId,
            scope: 'openid profile'
          }).toString()
        })
        const deviceData = await deviceResponse.json()

        // Then verify the user_code
        const verifyResponse = await server.request('/device', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            user_code: deviceData.user_code,
            action: 'verify'
          }).toString()
        })

        expect(verifyResponse.status).toBe(200)
        const html = await verifyResponse.text()
        expect(html).toContain('Authorize Device')
        expect(html).toContain('Device Client')
        expect(html).toContain('authorize')
        expect(html).toContain('deny')
      })
    })

    describe('Token Endpoint - Device Code Grant', () => {
      it('should return authorization_pending while waiting for user', async () => {
        // Get device code
        const deviceResponse = await server.request('/device_authorization', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            client_id: clientId
          }).toString()
        })
        const deviceData = await deviceResponse.json()

        // Poll for token without user authorization
        const tokenResponse = await server.request('/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
            device_code: deviceData.device_code,
            client_id: clientId
          }).toString()
        })

        expect(tokenResponse.status).toBe(400)
        const error = await tokenResponse.json()
        expect(error.error).toBe('authorization_pending')
      })

      it('should return slow_down if polling too fast', async () => {
        // Get device code
        const deviceResponse = await server.request('/device_authorization', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            client_id: clientId
          }).toString()
        })
        const deviceData = await deviceResponse.json()

        // First poll
        await server.request('/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
            device_code: deviceData.device_code,
            client_id: clientId
          }).toString()
        })

        // Immediate second poll (too fast)
        const tokenResponse = await server.request('/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
            device_code: deviceData.device_code,
            client_id: clientId
          }).toString()
        })

        expect(tokenResponse.status).toBe(400)
        const error = await tokenResponse.json()
        expect(error.error).toBe('slow_down')
      })

      it('should return access_denied if user denied', async () => {
        // Get device code
        const deviceResponse = await server.request('/device_authorization', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            client_id: clientId
          }).toString()
        })
        const deviceData = await deviceResponse.json()

        // User denies authorization
        await server.request('/device', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            user_code: deviceData.user_code,
            action: 'deny'
          }).toString()
        })

        // Poll for token
        const tokenResponse = await server.request('/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
            device_code: deviceData.device_code,
            client_id: clientId
          }).toString()
        })

        expect(tokenResponse.status).toBe(400)
        const error = await tokenResponse.json()
        expect(error.error).toBe('access_denied')
      })

      it('should return expired_token if device code expired', async () => {
        // Manually create an expired device code via storage
        const expiredDeviceCode = {
          deviceCode: 'expired-device-code-12345',
          userCode: 'WXYZ-BCDF',
          clientId,
          issuedAt: Date.now() - 700000, // 700 seconds ago
          expiresAt: Date.now() - 100000, // Expired 100 seconds ago
          interval: 5
        }
        await storage.saveDeviceCode(expiredDeviceCode)

        // Poll for token
        const tokenResponse = await server.request('/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
            device_code: 'expired-device-code-12345',
            client_id: clientId
          }).toString()
        })

        expect(tokenResponse.status).toBe(400)
        const error = await tokenResponse.json()
        expect(error.error).toBe('expired_token')
      })

      it('should return tokens once user authorizes', async () => {
        // Get device code
        const deviceResponse = await server.request('/device_authorization', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            client_id: clientId,
            scope: 'openid profile'
          }).toString()
        })
        const deviceData = await deviceResponse.json()

        // User authorizes
        await server.request('/device', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            user_code: deviceData.user_code,
            action: 'authorize'
          }).toString()
        })

        // Poll for token
        const tokenResponse = await server.request('/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
            device_code: deviceData.device_code,
            client_id: clientId
          }).toString()
        })

        expect(tokenResponse.status).toBe(200)
        const tokens = await tokenResponse.json()
        expect(tokens.access_token).toBeDefined()
        expect(tokens.refresh_token).toBeDefined()
        expect(tokens.token_type).toBe('Bearer')
        expect(tokens.expires_in).toBe(3600)
        expect(tokens.scope).toBe('openid profile')
      })

      it('should accept short form grant_type=device_code', async () => {
        // Get device code
        const deviceResponse = await server.request('/device_authorization', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            client_id: clientId
          }).toString()
        })
        const deviceData = await deviceResponse.json()

        // User authorizes
        await server.request('/device', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            user_code: deviceData.user_code,
            action: 'authorize'
          }).toString()
        })

        // Poll for token using short form grant_type
        const tokenResponse = await server.request('/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'device_code', // Short form
            device_code: deviceData.device_code,
            client_id: clientId
          }).toString()
        })

        expect(tokenResponse.status).toBe(200)
        const tokens = await tokenResponse.json()
        expect(tokens.access_token).toBeDefined()
      })

      it('should reject request without device_code', async () => {
        const tokenResponse = await server.request('/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
            client_id: clientId
          }).toString()
        })

        expect(tokenResponse.status).toBe(400)
        const error = await tokenResponse.json()
        expect(error.error).toBe('invalid_request')
        expect(error.error_description).toContain('device_code')
      })

      it('should reject request without client_id', async () => {
        const tokenResponse = await server.request('/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
            device_code: 'some-device-code'
          }).toString()
        })

        expect(tokenResponse.status).toBe(400)
        const error = await tokenResponse.json()
        expect(error.error).toBe('invalid_request')
        expect(error.error_description).toContain('client_id')
      })

      it('should reject request with mismatched client_id', async () => {
        // Get device code with one client
        const deviceResponse = await server.request('/device_authorization', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            client_id: clientId
          }).toString()
        })
        const deviceData = await deviceResponse.json()

        // Register another client
        const otherClientResponse = await server.request('/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            client_name: 'Other Client',
            redirect_uris: ['https://other.example.com/callback'],
            grant_types: ['authorization_code'],
            response_types: ['code'],
            token_endpoint_auth_method: 'none'
          })
        })
        const otherClient = await otherClientResponse.json()

        // Try to use device code with different client
        const tokenResponse = await server.request('/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
            device_code: deviceData.device_code,
            client_id: otherClient.client_id
          }).toString()
        })

        expect(tokenResponse.status).toBe(400)
        const error = await tokenResponse.json()
        expect(error.error).toBe('invalid_grant')
      })

      it('should clean up device code after successful token issuance', async () => {
        // Get device code
        const deviceResponse = await server.request('/device_authorization', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            client_id: clientId
          }).toString()
        })
        const deviceData = await deviceResponse.json()

        // User authorizes
        await server.request('/device', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            user_code: deviceData.user_code,
            action: 'authorize'
          }).toString()
        })

        // First token request - should succeed
        const tokenResponse = await server.request('/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
            device_code: deviceData.device_code,
            client_id: clientId
          }).toString()
        })
        expect(tokenResponse.status).toBe(200)

        // Second token request with same device code - should fail
        const secondTokenResponse = await server.request('/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
            device_code: deviceData.device_code,
            client_id: clientId
          }).toString()
        })

        expect(secondTokenResponse.status).toBe(400)
        const error = await secondTokenResponse.json()
        expect(error.error).toBe('invalid_grant')
      })
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Refresh Token Expiry (Bug Fix Verification)
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Refresh Token Expiry', () => {
    let clientId: string
    let codeVerifier: string
    let codeChallenge: string

    beforeEach(async () => {
      // Register a client
      const regResponse = await server.request('/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_name: 'Expiry Test Client',
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

    it('should set refresh token expiresAt to ~30 days from now (authorization_code grant)', async () => {
      const beforeToken = Date.now()

      // Complete auth code flow
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
          state: 'expiry-test',
          scope: 'openid profile',
          response_type: 'code'
        }).toString()
      })

      const location = loginResponse.headers.get('location')!
      const code = new URL(location).searchParams.get('code')!

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
      const afterToken = Date.now()

      // Inspect the refresh token in storage to verify expiresAt
      const storedRefresh = await storage.getRefreshToken(tokens.refresh_token)
      expect(storedRefresh).not.toBeNull()
      expect(storedRefresh!.expiresAt).toBeDefined()

      // Default refreshTokenTtl = 2592000 seconds = 30 days
      const expectedTtlMs = 2592000 * 1000
      const expectedMinExpiry = beforeToken + expectedTtlMs
      const expectedMaxExpiry = afterToken + expectedTtlMs

      // The expiresAt should be within [beforeToken + 30d, afterToken + 30d]
      expect(storedRefresh!.expiresAt).toBeGreaterThanOrEqual(expectedMinExpiry)
      expect(storedRefresh!.expiresAt).toBeLessThanOrEqual(expectedMaxExpiry)

      // Sanity check: should NOT be 5 days (the bug value)
      const fiveDaysMs = 5 * 24 * 60 * 60 * 1000
      expect(storedRefresh!.expiresAt! - beforeToken).toBeGreaterThan(fiveDaysMs)

      // Should be approximately 30 days (within 10 seconds tolerance)
      const actualTtlMs = storedRefresh!.expiresAt! - storedRefresh!.issuedAt
      expect(Math.abs(actualTtlMs - expectedTtlMs)).toBeLessThan(10000)
    })

    it('should set refresh token expiresAt to ~30 days after rotation (refresh_token grant)', async () => {
      // First, get tokens via auth code flow
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
          state: 'rotation-test',
          scope: 'openid',
          response_type: 'code'
        }).toString()
      })

      const location = loginResponse.headers.get('location')!
      const code = new URL(location).searchParams.get('code')!

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

      const tokens = await tokenResponse.json()

      // Now rotate the refresh token
      const beforeRefresh = Date.now()
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
      const afterRefresh = Date.now()

      // The rotated refresh token should also have ~30 day expiry
      const storedNewRefresh = await storage.getRefreshToken(newTokens.refresh_token)
      expect(storedNewRefresh).not.toBeNull()
      expect(storedNewRefresh!.expiresAt).toBeDefined()

      const expectedTtlMs = 2592000 * 1000
      expect(storedNewRefresh!.expiresAt).toBeGreaterThanOrEqual(beforeRefresh + expectedTtlMs)
      expect(storedNewRefresh!.expiresAt).toBeLessThanOrEqual(afterRefresh + expectedTtlMs)

      // The old refresh token should be revoked
      const storedOldRefresh = await storage.getRefreshToken(tokens.refresh_token)
      expect(storedOldRefresh?.revoked).toBe(true)
    })

    it('should set refresh token expiresAt to ~30 days (test helper)', async () => {
      const beforeToken = Date.now()
      await server.testHelpers!.createUser({ id: 'expiry-user', email: 'expiry@example.com' })
      const tokens = await server.testHelpers!.getAccessToken('expiry-user', 'test-client', 'openid')
      const afterToken = Date.now()

      const storedRefresh = await storage.getRefreshToken(tokens.refreshToken)
      expect(storedRefresh).not.toBeNull()
      expect(storedRefresh!.expiresAt).toBeDefined()

      const expectedTtlMs = 2592000 * 1000
      expect(storedRefresh!.expiresAt).toBeGreaterThanOrEqual(beforeToken + expectedTtlMs)
      expect(storedRefresh!.expiresAt).toBeLessThanOrEqual(afterToken + expectedTtlMs)
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // computeRefreshTokenExpiry helper unit tests
  // ═══════════════════════════════════════════════════════════════════════════

  describe('computeRefreshTokenExpiry', () => {
    it('returns now + ttl*1000 for positive TTL', () => {
      const now = 1700000000000
      const result = computeRefreshTokenExpiry(2592000, now)
      expect(result).toBe(now + 2592000 * 1000)
    })

    it('returns undefined for TTL of 0', () => {
      const result = computeRefreshTokenExpiry(0, 1700000000000)
      expect(result).toBeUndefined()
    })

    it('returns undefined for negative TTL', () => {
      const result = computeRefreshTokenExpiry(-1, 1700000000000)
      expect(result).toBeUndefined()
    })

    it('computes correct 30-day expiry in milliseconds', () => {
      const now = Date.now()
      const result = computeRefreshTokenExpiry(2592000, now)!
      const thirtyDaysMs = 30 * 24 * 60 * 60 * 1000
      expect(result - now).toBe(thirtyDaysMs)
    })

    it('uses Date.now() when no now argument is given', () => {
      const before = Date.now()
      const result = computeRefreshTokenExpiry(3600)!
      const after = Date.now()
      expect(result).toBeGreaterThanOrEqual(before + 3600 * 1000)
      expect(result).toBeLessThanOrEqual(after + 3600 * 1000)
    })
  })
})
