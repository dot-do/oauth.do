import { describe, it, expect, beforeEach } from 'vitest'
import { createOAuth21Server, MemoryOAuthStorage } from './index'

describe('Dev Mode', () => {
  describe('createOAuth21Server with devMode', () => {
    it('creates server with dev mode enabled', () => {
      const server = createOAuth21Server({
        issuer: 'https://test.mcp.do',
        storage: new MemoryOAuthStorage(),
        devMode: {
          enabled: true,
          users: [
            { id: 'test-user', email: 'test@example.com', password: 'test123', name: 'Test User' }
          ]
        }
      })

      expect(server).toBeDefined()
      expect(server.testHelpers).toBeDefined()
    })

    it('throws when neither devMode nor upstream is provided', () => {
      expect(() => {
        createOAuth21Server({
          issuer: 'https://test.mcp.do',
          storage: new MemoryOAuthStorage(),
        })
      }).toThrow('Either upstream configuration or devMode must be provided')
    })

    it('allows allowAnyCredentials option', () => {
      const server = createOAuth21Server({
        issuer: 'https://test.mcp.do',
        storage: new MemoryOAuthStorage(),
        devMode: {
          enabled: true,
          allowAnyCredentials: true
        }
      })

      expect(server.testHelpers).toBeDefined()
    })
  })

  describe('TestHelpers', () => {
    let server: ReturnType<typeof createOAuth21Server>
    let storage: MemoryOAuthStorage

    beforeEach(() => {
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
        }
      })
    })

    describe('validateCredentials', () => {
      it('validates correct credentials', async () => {
        const user = await server.testHelpers!.validateCredentials('test@example.com', 'test123')
        expect(user).not.toBeNull()
        expect(user?.id).toBe('test-user')
        expect(user?.email).toBe('test@example.com')
      })

      it('rejects incorrect password when allowAnyCredentials is false', async () => {
        // Create a server without allowAnyCredentials
        const strictServer = createOAuth21Server({
          issuer: 'https://test.mcp.do',
          storage: new MemoryOAuthStorage(),
          devMode: {
            enabled: true,
            users: [
              { id: 'test-user', email: 'test@example.com', password: 'test123', name: 'Test User' }
            ],
            allowAnyCredentials: false
          }
        })

        const user = await strictServer.testHelpers!.validateCredentials('test@example.com', 'wrong')
        expect(user).toBeNull()
      })

      it('creates user on the fly with allowAnyCredentials', async () => {
        const user = await server.testHelpers!.validateCredentials('new@example.com', 'newpass')
        expect(user).not.toBeNull()
        expect(user?.email).toBe('new@example.com')
      })
    })

    describe('createUser', () => {
      it('creates a user in storage', async () => {
        const user = await server.testHelpers!.createUser({
          id: 'new-user',
          email: 'new@example.com',
          name: 'New User'
        })

        expect(user.id).toBe('new-user')
        expect(user.email).toBe('new@example.com')

        // Verify in storage
        const stored = await storage.getUser('new-user')
        expect(stored).not.toBeNull()
        expect(stored?.email).toBe('new@example.com')
      })

      it('creates user with password for login', async () => {
        await server.testHelpers!.createUser({
          id: 'login-user',
          email: 'login@example.com',
          password: 'mypassword'
        })

        // Should now be able to validate
        const validated = await server.testHelpers!.validateCredentials('login@example.com', 'mypassword')
        expect(validated).not.toBeNull()
        expect(validated?.id).toBe('login-user')
      })
    })

    describe('getAccessToken', () => {
      it('creates access and refresh tokens', async () => {
        // First create a user
        await server.testHelpers!.createUser({
          id: 'token-user',
          email: 'token@example.com'
        })

        const tokens = await server.testHelpers!.getAccessToken('token-user', 'test-client', 'openid profile')

        expect(tokens.accessToken).toBeDefined()
        expect(tokens.accessToken.length).toBeGreaterThan(32)
        expect(tokens.refreshToken).toBeDefined()
        expect(tokens.refreshToken.length).toBeGreaterThan(32)
        expect(tokens.expiresIn).toBe(3600)

        // Verify token is in storage
        const storedToken = await storage.getAccessToken(tokens.accessToken)
        expect(storedToken).not.toBeNull()
        expect(storedToken?.userId).toBe('token-user')
        expect(storedToken?.clientId).toBe('test-client')
      })
    })

    describe('createAuthorizationCode', () => {
      it('creates an authorization code', async () => {
        const code = await server.testHelpers!.createAuthorizationCode({
          clientId: 'test-client',
          userId: 'test-user',
          redirectUri: 'https://example.com/callback',
          scope: 'openid profile',
          codeChallenge: 'test-challenge'
        })

        expect(code).toBeDefined()
        expect(code.length).toBeGreaterThan(32)

        // Verify code is in storage and can be consumed
        const storedCode = await storage.consumeAuthorizationCode(code)
        expect(storedCode).not.toBeNull()
        expect(storedCode?.clientId).toBe('test-client')
        expect(storedCode?.userId).toBe('test-user')
      })
    })

    describe('getSessionCookies', () => {
      it('returns session cookies for Playwright', async () => {
        await server.testHelpers!.createUser({
          id: 'cookie-user',
          email: 'cookie@example.com'
        })

        const cookies = await server.testHelpers!.getSessionCookies('cookie-user')

        expect(cookies).toHaveLength(1)
        expect(cookies[0].name).toBe('oauth_access_token')
        expect(cookies[0].value).toBeDefined()
        expect(cookies[0].httpOnly).toBe(true)
        expect(cookies[0].secure).toBe(true)
      })
    })
  })
})

describe('Dev Mode Endpoints', () => {
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
        ]
      }
    })

    // Register a test client
    await storage.saveClient({
      clientId: 'test-client',
      clientName: 'Test Client',
      redirectUris: ['https://example.com/callback'],
      grantTypes: ['authorization_code', 'refresh_token'],
      responseTypes: ['code'],
      tokenEndpointAuthMethod: 'none',
      createdAt: Date.now()
    })
  })

  it('shows login form on /authorize in dev mode', async () => {
    const response = await server.request('/authorize?response_type=code&client_id=test-client&redirect_uri=https://example.com/callback&code_challenge=test123&code_challenge_method=S256')

    expect(response.status).toBe(200)
    const html = await response.text()
    expect(html).toContain('Sign In')
    expect(html).toContain('Development Mode')
    expect(html).toContain('test-client')
  })

  it('rejects /login when dev mode is not enabled', async () => {
    const prodServer = createOAuth21Server({
      issuer: 'https://prod.mcp.do',
      storage: new MemoryOAuthStorage(),
      upstream: {
        provider: 'workos',
        apiKey: 'test-key',
        clientId: 'test-client'
      }
    })

    const formData = new FormData()
    formData.append('email', 'test@example.com')
    formData.append('password', 'test123')

    const response = await prodServer.request('/login', {
      method: 'POST',
      body: formData
    })

    expect(response.status).toBe(400)
    const json = await response.json()
    expect(json.error).toBe('invalid_request')
  })
})
