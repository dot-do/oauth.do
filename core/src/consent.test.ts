import { describe, it, expect, beforeEach } from 'vitest'
import { createOAuth21Server, MemoryOAuthStorage, generateCodeChallenge, generateCodeVerifier } from 'id.org.ai/oauth'
import { consentCoversScopes, getScopeDescription, generateConsentScreenHtml } from 'id.org.ai/oauth'

// ═══════════════════════════════════════════════════════════════════════════
// Unit Tests - Consent Utilities
// ═══════════════════════════════════════════════════════════════════════════

describe('Consent Utilities', () => {
  describe('getScopeDescription', () => {
    it('returns description for known scopes', () => {
      expect(getScopeDescription('openid')).toBe('Verify your identity')
      expect(getScopeDescription('profile')).toBe('View your profile information (name, picture)')
      expect(getScopeDescription('email')).toBe('View your email address')
      expect(getScopeDescription('offline_access')).toBe('Maintain access when you are not actively using the app')
      expect(getScopeDescription('mcp:read')).toBe('Read data through the Model Context Protocol')
      expect(getScopeDescription('mcp:write')).toBe('Create and modify data through the Model Context Protocol')
      expect(getScopeDescription('mcp:admin')).toBe('Full administrative access through the Model Context Protocol')
    })

    it('returns generic description for unknown scopes', () => {
      expect(getScopeDescription('custom:scope')).toBe('Access: custom:scope')
      expect(getScopeDescription('foo')).toBe('Access: foo')
    })
  })

  describe('consentCoversScopes', () => {
    it('returns true when all requested scopes are covered', () => {
      const consent = {
        userId: 'user-1',
        clientId: 'client-1',
        scopes: ['openid', 'profile', 'email'],
        createdAt: Date.now(),
        updatedAt: Date.now(),
      }
      expect(consentCoversScopes(consent, ['openid', 'profile'])).toBe(true)
      expect(consentCoversScopes(consent, ['openid'])).toBe(true)
      expect(consentCoversScopes(consent, ['openid', 'profile', 'email'])).toBe(true)
    })

    it('returns true for empty requested scopes', () => {
      const consent = {
        userId: 'user-1',
        clientId: 'client-1',
        scopes: ['openid'],
        createdAt: Date.now(),
        updatedAt: Date.now(),
      }
      expect(consentCoversScopes(consent, [])).toBe(true)
    })

    it('returns false when requested scopes exceed consented scopes', () => {
      const consent = {
        userId: 'user-1',
        clientId: 'client-1',
        scopes: ['openid', 'profile'],
        createdAt: Date.now(),
        updatedAt: Date.now(),
      }
      expect(consentCoversScopes(consent, ['openid', 'mcp:write'])).toBe(false)
      expect(consentCoversScopes(consent, ['mcp:admin'])).toBe(false)
    })
  })

  describe('generateConsentScreenHtml', () => {
    it('generates valid HTML with all required elements', () => {
      const html = generateConsentScreenHtml({
        issuer: 'https://test.mcp.do',
        clientName: 'Test Client',
        clientId: 'client-123',
        redirectUri: 'https://example.com/callback',
        scopes: ['openid', 'profile'],
        consentToken: 'test-consent-token',
      })

      expect(html).toContain('<!DOCTYPE html>')
      expect(html).toContain('Authorize Access')
      expect(html).toContain('Test Client')
      expect(html).toContain('wants to access your account')
      expect(html).toContain('example.com')
      expect(html).toContain('openid')
      expect(html).toContain('profile')
      expect(html).toContain('test-consent-token')
      expect(html).toContain('Allow')
      expect(html).toContain('Deny')
      expect(html).toContain('client-123')
    })

    it('escapes HTML in client name to prevent XSS', () => {
      const html = generateConsentScreenHtml({
        issuer: 'https://test.mcp.do',
        clientName: '<script>alert("xss")</script>',
        clientId: 'client-123',
        redirectUri: 'https://example.com/callback',
        scopes: ['openid'],
        consentToken: 'token',
      })

      expect(html).not.toContain('<script>')
      expect(html).toContain('&lt;script&gt;')
    })

    it('escapes HTML in consent token to prevent injection', () => {
      const html = generateConsentScreenHtml({
        issuer: 'https://test.mcp.do',
        clientName: 'Test',
        clientId: 'client-123',
        redirectUri: 'https://example.com/callback',
        scopes: ['openid'],
        consentToken: '"><script>alert(1)</script>',
      })

      expect(html).not.toContain('"><script>')
      expect(html).toContain('&quot;&gt;&lt;script&gt;')
    })

    it('handles invalid redirect URI gracefully', () => {
      const html = generateConsentScreenHtml({
        issuer: 'https://test.mcp.do',
        clientName: 'Test',
        clientId: 'client-123',
        redirectUri: 'not-a-valid-url',
        scopes: ['openid'],
        consentToken: 'token',
      })

      // Should use the raw string as fallback
      expect(html).toContain('not-a-valid-url')
    })

    it('includes scope descriptions', () => {
      const html = generateConsentScreenHtml({
        issuer: 'https://test.mcp.do',
        clientName: 'Test',
        clientId: 'client-123',
        redirectUri: 'https://example.com/callback',
        scopes: ['mcp:read', 'mcp:write'],
        consentToken: 'token',
      })

      expect(html).toContain('Read data through the Model Context Protocol')
      expect(html).toContain('Create and modify data through the Model Context Protocol')
    })
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// Unit Tests - MemoryOAuthStorage Consent Operations
// ═══════════════════════════════════════════════════════════════════════════

describe('MemoryOAuthStorage - Consent Operations', () => {
  let storage: MemoryOAuthStorage

  beforeEach(() => {
    storage = new MemoryOAuthStorage()
  })

  it('saves and retrieves consent', async () => {
    const consent = {
      userId: 'user-1',
      clientId: 'client-1',
      scopes: ['openid', 'profile'],
      createdAt: Date.now(),
      updatedAt: Date.now(),
    }

    await storage.saveConsent(consent)

    const retrieved = await storage.getConsent('user-1', 'client-1')
    expect(retrieved).not.toBeNull()
    expect(retrieved?.userId).toBe('user-1')
    expect(retrieved?.clientId).toBe('client-1')
    expect(retrieved?.scopes).toEqual(['openid', 'profile'])
  })

  it('returns null for non-existent consent', async () => {
    const result = await storage.getConsent('user-1', 'client-1')
    expect(result).toBeNull()
  })

  it('updates existing consent (upsert)', async () => {
    const now = Date.now()

    await storage.saveConsent({
      userId: 'user-1',
      clientId: 'client-1',
      scopes: ['openid'],
      createdAt: now,
      updatedAt: now,
    })

    await storage.saveConsent({
      userId: 'user-1',
      clientId: 'client-1',
      scopes: ['openid', 'profile', 'email'],
      createdAt: now,
      updatedAt: now + 1000,
    })

    const retrieved = await storage.getConsent('user-1', 'client-1')
    expect(retrieved?.scopes).toEqual(['openid', 'profile', 'email'])
    expect(retrieved?.updatedAt).toBe(now + 1000)
  })

  it('revokes consent', async () => {
    await storage.saveConsent({
      userId: 'user-1',
      clientId: 'client-1',
      scopes: ['openid'],
      createdAt: Date.now(),
      updatedAt: Date.now(),
    })

    await storage.revokeConsent('user-1', 'client-1')

    const retrieved = await storage.getConsent('user-1', 'client-1')
    expect(retrieved).toBeNull()
  })

  it('lists user consents', async () => {
    const now = Date.now()

    await storage.saveConsent({
      userId: 'user-1',
      clientId: 'client-a',
      scopes: ['openid'],
      createdAt: now,
      updatedAt: now,
    })

    await storage.saveConsent({
      userId: 'user-1',
      clientId: 'client-b',
      scopes: ['openid', 'profile'],
      createdAt: now,
      updatedAt: now,
    })

    await storage.saveConsent({
      userId: 'user-2',
      clientId: 'client-a',
      scopes: ['openid'],
      createdAt: now,
      updatedAt: now,
    })

    const user1Consents = await storage.listUserConsents('user-1')
    expect(user1Consents).toHaveLength(2)
    expect(user1Consents.map((c) => c.clientId).sort()).toEqual(['client-a', 'client-b'])

    const user2Consents = await storage.listUserConsents('user-2')
    expect(user2Consents).toHaveLength(1)
  })

  it('isolates consent by user+client pair', async () => {
    const now = Date.now()

    await storage.saveConsent({
      userId: 'user-1',
      clientId: 'client-1',
      scopes: ['openid'],
      createdAt: now,
      updatedAt: now,
    })

    await storage.saveConsent({
      userId: 'user-1',
      clientId: 'client-2',
      scopes: ['mcp:write'],
      createdAt: now,
      updatedAt: now,
    })

    const c1 = await storage.getConsent('user-1', 'client-1')
    const c2 = await storage.getConsent('user-1', 'client-2')

    expect(c1?.scopes).toEqual(['openid'])
    expect(c2?.scopes).toEqual(['mcp:write'])
  })

  it('clears consents along with all other data', () => {
    storage.saveConsent({
      userId: 'user-1',
      clientId: 'client-1',
      scopes: ['openid'],
      createdAt: Date.now(),
      updatedAt: Date.now(),
    })

    storage.clear()

    // After clear, consent should be gone
    storage.getConsent('user-1', 'client-1').then((c) => expect(c).toBeNull())
  })
})

// ═══════════════════════════════════════════════════════════════════════════
// E2E Tests - Consent Flow with OAuth Server
// ═══════════════════════════════════════════════════════════════════════════

describe('Consent Flow E2E', () => {
  let storage: MemoryOAuthStorage

  // Helper to create a server with consent enabled (not skipped)
  function createServerWithConsent(opts?: { trustedClientIds?: string[]; skipConsent?: boolean }) {
    storage = new MemoryOAuthStorage()
    return createOAuth21Server({
      issuer: 'https://test.mcp.do',
      storage,
      devMode: {
        enabled: true,
        users: [{ id: 'test-user', email: 'test@example.com', password: 'test123', name: 'Test User' }],
        allowAnyCredentials: true,
      },
      enableDynamicRegistration: true,
      scopes: ['openid', 'profile', 'email', 'mcp:read', 'mcp:write'],
      trustedClientIds: opts?.trustedClientIds ?? [],
      skipConsent: opts?.skipConsent ?? false,
    })
  }

  // Helper to register a third-party client
  async function registerClient(server: ReturnType<typeof createOAuth21Server>, name = 'Third Party MCP Client') {
    const response = await server.request('/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_name: name,
        redirect_uris: ['https://third-party.example.com/callback'],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
      }),
    })
    return response.json() as Promise<{ client_id: string; client_name: string }>
  }

  // Helper to do a login POST and return the response
  async function doLogin(
    server: ReturnType<typeof createOAuth21Server>,
    clientId: string,
    codeChallenge: string,
    opts?: { scope?: string; redirectUri?: string }
  ) {
    return server.request('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        email: 'test@example.com',
        password: 'test123',
        client_id: clientId,
        redirect_uri: opts?.redirectUri ?? 'https://third-party.example.com/callback',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        state: 'test-state',
        scope: opts?.scope ?? 'openid profile',
        response_type: 'code',
      }).toString(),
    })
  }

  describe('Third-party client shows consent screen', () => {
    it('shows consent screen for a third-party client on first login', async () => {
      const server = createServerWithConsent()
      const client = await registerClient(server)
      const codeVerifier = generateCodeVerifier()
      const codeChallenge = await generateCodeChallenge(codeVerifier)

      const response = await doLogin(server, client.client_id, codeChallenge)

      // Should return 200 with consent HTML, NOT a 302 redirect
      expect(response.status).toBe(200)
      const html = await response.text()
      expect(html).toContain('Authorize Access')
      expect(html).toContain('Third Party MCP Client')
      expect(html).toContain('third-party.example.com')
      expect(html).toContain('openid')
      expect(html).toContain('profile')
      expect(html).toContain('Allow')
      expect(html).toContain('Deny')
    })

    it('includes scope descriptions in the consent screen', async () => {
      const server = createServerWithConsent()
      const client = await registerClient(server)
      const codeVerifier = generateCodeVerifier()
      const codeChallenge = await generateCodeChallenge(codeVerifier)

      const response = await doLogin(server, client.client_id, codeChallenge, { scope: 'openid mcp:read mcp:write' })

      expect(response.status).toBe(200)
      const html = await response.text()
      expect(html).toContain('Verify your identity')
      expect(html).toContain('Read data through the Model Context Protocol')
      expect(html).toContain('Create and modify data through the Model Context Protocol')
    })
  })

  describe('First-party client skips consent', () => {
    it('skips consent for clients in trustedClientIds list', async () => {
      const server = createServerWithConsent({ trustedClientIds: ['my-own-spa'] })

      // Register client with the trusted ID
      await storage.saveClient({
        clientId: 'my-own-spa',
        clientName: 'My SPA',
        redirectUris: ['https://my-spa.example.com/callback'],
        grantTypes: ['authorization_code', 'refresh_token'],
        responseTypes: ['code'],
        tokenEndpointAuthMethod: 'none',
        createdAt: Date.now(),
      })

      const codeVerifier = generateCodeVerifier()
      const codeChallenge = await generateCodeChallenge(codeVerifier)

      const response = await server.request('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          email: 'test@example.com',
          password: 'test123',
          client_id: 'my-own-spa',
          redirect_uri: 'https://my-spa.example.com/callback',
          code_challenge: codeChallenge,
          code_challenge_method: 'S256',
          state: 'test-state',
          scope: 'openid profile',
          response_type: 'code',
        }).toString(),
      })

      // Should redirect directly (302), no consent screen
      expect(response.status).toBe(302)
      const location = response.headers.get('location')!
      expect(location).toContain('https://my-spa.example.com/callback')
      expect(location).toContain('code=')
    })

    it('skips consent when skipConsent is true', async () => {
      const server = createServerWithConsent({ skipConsent: true })
      const client = await registerClient(server)
      const codeVerifier = generateCodeVerifier()
      const codeChallenge = await generateCodeChallenge(codeVerifier)

      const response = await doLogin(server, client.client_id, codeChallenge)

      // Should redirect directly (302), no consent screen
      expect(response.status).toBe(302)
      const location = response.headers.get('location')!
      expect(location).toContain('https://third-party.example.com/callback')
      expect(location).toContain('code=')
    })
  })

  describe('Consent Allow flow', () => {
    it('completes full flow: login -> consent -> allow -> token', async () => {
      const server = createServerWithConsent()
      const client = await registerClient(server)
      const codeVerifier = generateCodeVerifier()
      const codeChallenge = await generateCodeChallenge(codeVerifier)

      // Step 1: Login (should show consent screen)
      const loginResponse = await doLogin(server, client.client_id, codeChallenge)
      expect(loginResponse.status).toBe(200)
      const html = await loginResponse.text()

      // Extract consent_token from form
      const tokenMatch = html.match(/name="consent_token"\s+value="([^"]+)"/)
      expect(tokenMatch).not.toBeNull()
      const consentToken = tokenMatch![1]

      // Step 2: Submit consent (allow)
      const consentResponse = await server.request('/consent', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          consent_token: consentToken,
          action: 'allow',
        }).toString(),
      })

      expect(consentResponse.status).toBe(302)
      const location = consentResponse.headers.get('location')!
      expect(location).toContain('https://third-party.example.com/callback')
      expect(location).toContain('code=')
      expect(location).toContain('state=test-state')

      // Extract auth code
      const authCode = new URL(location).searchParams.get('code')!
      expect(authCode).toBeDefined()

      // Step 3: Exchange code for tokens
      const tokenResponse = await server.request('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: authCode,
          client_id: client.client_id,
          redirect_uri: 'https://third-party.example.com/callback',
          code_verifier: codeVerifier,
        }).toString(),
      })

      expect(tokenResponse.status).toBe(200)
      const tokens = await tokenResponse.json()
      expect(tokens.access_token).toBeDefined()
      expect(tokens.refresh_token).toBeDefined()
      expect(tokens.token_type).toBe('Bearer')
    })

    it('stores consent so subsequent logins skip the consent screen', async () => {
      const server = createServerWithConsent()
      const client = await registerClient(server)

      // First auth: login + consent
      const codeVerifier1 = generateCodeVerifier()
      const codeChallenge1 = await generateCodeChallenge(codeVerifier1)

      const loginResponse1 = await doLogin(server, client.client_id, codeChallenge1)
      expect(loginResponse1.status).toBe(200)
      const html1 = await loginResponse1.text()
      const tokenMatch = html1.match(/name="consent_token"\s+value="([^"]+)"/)!
      const consentToken = tokenMatch[1]

      // Allow
      await server.request('/consent', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          consent_token: consentToken,
          action: 'allow',
        }).toString(),
      })

      // Second auth: should skip consent
      const codeVerifier2 = generateCodeVerifier()
      const codeChallenge2 = await generateCodeChallenge(codeVerifier2)

      const loginResponse2 = await doLogin(server, client.client_id, codeChallenge2)

      // Should redirect directly (302), consent already given
      expect(loginResponse2.status).toBe(302)
      const location = loginResponse2.headers.get('location')!
      expect(location).toContain('code=')
    })

    it('merges scopes when consenting to additional scopes', async () => {
      const server = createServerWithConsent()
      const client = await registerClient(server)

      // First consent: openid profile
      const cv1 = generateCodeVerifier()
      const cc1 = await generateCodeChallenge(cv1)

      const login1 = await doLogin(server, client.client_id, cc1, { scope: 'openid profile' })
      expect(login1.status).toBe(200)
      const html1 = await login1.text()
      const tm1 = html1.match(/name="consent_token"\s+value="([^"]+)"/)!

      await server.request('/consent', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ consent_token: tm1[1], action: 'allow' }).toString(),
      })

      // Second request: openid profile + mcp:read (new scope)
      // Should show consent screen again because mcp:read is not yet consented
      const cv2 = generateCodeVerifier()
      const cc2 = await generateCodeChallenge(cv2)

      const login2 = await doLogin(server, client.client_id, cc2, { scope: 'openid profile mcp:read' })
      expect(login2.status).toBe(200) // Consent screen shown again

      const html2 = await login2.text()
      expect(html2).toContain('mcp:read')

      const tm2 = html2.match(/name="consent_token"\s+value="([^"]+)"/)!
      await server.request('/consent', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ consent_token: tm2[1], action: 'allow' }).toString(),
      })

      // Verify merged consent covers all three scopes
      const consent = await storage.getConsent('test-user', client.client_id)
      expect(consent).not.toBeNull()
      expect(consent!.scopes).toContain('openid')
      expect(consent!.scopes).toContain('profile')
      expect(consent!.scopes).toContain('mcp:read')

      // Third request with subset of consented scopes: should skip consent
      const cv3 = generateCodeVerifier()
      const cc3 = await generateCodeChallenge(cv3)

      const login3 = await doLogin(server, client.client_id, cc3, { scope: 'openid profile mcp:read' })
      expect(login3.status).toBe(302)
    })
  })

  describe('Consent Deny flow', () => {
    it('redirects with error=access_denied when user denies', async () => {
      const server = createServerWithConsent()
      const client = await registerClient(server)
      const codeVerifier = generateCodeVerifier()
      const codeChallenge = await generateCodeChallenge(codeVerifier)

      // Login (shows consent screen)
      const loginResponse = await doLogin(server, client.client_id, codeChallenge)
      expect(loginResponse.status).toBe(200)
      const html = await loginResponse.text()
      const tokenMatch = html.match(/name="consent_token"\s+value="([^"]+)"/)!
      const consentToken = tokenMatch[1]

      // Deny consent
      const consentResponse = await server.request('/consent', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          consent_token: consentToken,
          action: 'deny',
        }).toString(),
      })

      expect(consentResponse.status).toBe(302)
      const location = consentResponse.headers.get('location')!
      expect(location).toContain('error=access_denied')
      expect(location).toContain('The+user+denied')
    })

    it('does not store consent when user denies', async () => {
      const server = createServerWithConsent()
      const client = await registerClient(server)
      const codeVerifier = generateCodeVerifier()
      const codeChallenge = await generateCodeChallenge(codeVerifier)

      // Login (shows consent screen)
      const loginResponse = await doLogin(server, client.client_id, codeChallenge)
      const html = await loginResponse.text()
      const tokenMatch = html.match(/name="consent_token"\s+value="([^"]+)"/)!

      // Deny
      await server.request('/consent', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          consent_token: tokenMatch[1],
          action: 'deny',
        }).toString(),
      })

      // No consent should be stored
      const consent = await storage.getConsent('test-user', client.client_id)
      expect(consent).toBeNull()
    })
  })

  describe('Consent error handling', () => {
    it('rejects consent POST without consent_token', async () => {
      const server = createServerWithConsent()

      const response = await server.request('/consent', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          action: 'allow',
        }).toString(),
      })

      expect(response.status).toBe(400)
      const error = await response.json()
      expect(error.error).toBe('invalid_request')
      expect(error.error_description).toContain('consent_token')
    })

    it('rejects consent POST with invalid action', async () => {
      const server = createServerWithConsent()

      const response = await server.request('/consent', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          consent_token: 'some-token',
          action: 'maybe',
        }).toString(),
      })

      expect(response.status).toBe(400)
      const error = await response.json()
      expect(error.error).toBe('invalid_request')
      expect(error.error_description).toContain('action')
    })

    it('rejects consent POST with expired/invalid consent token', async () => {
      const server = createServerWithConsent()

      const response = await server.request('/consent', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          consent_token: 'nonexistent-token',
          action: 'allow',
        }).toString(),
      })

      expect(response.status).toBe(400)
      const error = await response.json()
      expect(error.error).toBe('invalid_request')
      expect(error.error_description).toContain('Invalid or expired')
    })

    it('prevents consent token reuse (single-use)', async () => {
      const server = createServerWithConsent()
      const client = await registerClient(server)
      const codeVerifier = generateCodeVerifier()
      const codeChallenge = await generateCodeChallenge(codeVerifier)

      // Login (shows consent screen)
      const loginResponse = await doLogin(server, client.client_id, codeChallenge)
      const html = await loginResponse.text()
      const tokenMatch = html.match(/name="consent_token"\s+value="([^"]+)"/)!
      const consentToken = tokenMatch[1]

      // First use: allow
      const firstResponse = await server.request('/consent', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          consent_token: consentToken,
          action: 'allow',
        }).toString(),
      })
      expect(firstResponse.status).toBe(302)

      // Second use: should fail (token consumed)
      const secondResponse = await server.request('/consent', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          consent_token: consentToken,
          action: 'allow',
        }).toString(),
      })
      expect(secondResponse.status).toBe(400)
      const error = await secondResponse.json()
      expect(error.error).toBe('invalid_request')
    })
  })

  describe('Consent state preservation', () => {
    it('preserves client state parameter through consent flow', async () => {
      const server = createServerWithConsent()
      const client = await registerClient(server)
      const codeVerifier = generateCodeVerifier()
      const codeChallenge = await generateCodeChallenge(codeVerifier)

      // Login with specific state
      const loginResponse = await doLogin(server, client.client_id, codeChallenge)
      expect(loginResponse.status).toBe(200)
      const html = await loginResponse.text()
      const tokenMatch = html.match(/name="consent_token"\s+value="([^"]+)"/)!

      // Allow
      const consentResponse = await server.request('/consent', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          consent_token: tokenMatch[1],
          action: 'allow',
        }).toString(),
      })

      expect(consentResponse.status).toBe(302)
      const location = consentResponse.headers.get('location')!
      const url = new URL(location)
      expect(url.searchParams.get('state')).toBe('test-state')
    })

    it('preserves PKCE code challenge through consent flow', async () => {
      const server = createServerWithConsent()
      const client = await registerClient(server)
      const codeVerifier = generateCodeVerifier()
      const codeChallenge = await generateCodeChallenge(codeVerifier)

      // Login -> consent -> allow
      const loginResponse = await doLogin(server, client.client_id, codeChallenge)
      const html = await loginResponse.text()
      const tokenMatch = html.match(/name="consent_token"\s+value="([^"]+)"/)!

      const consentResponse = await server.request('/consent', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          consent_token: tokenMatch[1],
          action: 'allow',
        }).toString(),
      })

      const location = consentResponse.headers.get('location')!
      const authCode = new URL(location).searchParams.get('code')!

      // Token exchange with original code_verifier should work
      const tokenResponse = await server.request('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: authCode,
          client_id: client.client_id,
          redirect_uri: 'https://third-party.example.com/callback',
          code_verifier: codeVerifier,
        }).toString(),
      })

      expect(tokenResponse.status).toBe(200)
      const tokens = await tokenResponse.json()
      expect(tokens.access_token).toBeDefined()
    })
  })
})
