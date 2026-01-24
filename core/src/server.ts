/**
 * @dotdo/oauth - OAuth 2.1 Server Implementation
 *
 * Creates a Hono app that implements OAuth 2.1 authorization server endpoints:
 * - /.well-known/oauth-authorization-server (RFC 8414)
 * - /.well-known/oauth-protected-resource (draft-ietf-oauth-resource-metadata)
 * - /authorize (authorization endpoint)
 * - /callback (upstream OAuth callback)
 * - /token (token endpoint)
 * - /register (dynamic client registration - RFC 7591)
 * - /revoke (token revocation - RFC 7009)
 *
 * This server acts as a federated OAuth 2.1 server:
 * - It is an OAuth SERVER to downstream clients (Claude, ChatGPT, etc.)
 * - It is an OAuth CLIENT to upstream providers (WorkOS, Auth0, etc.)
 */

import { Hono } from 'hono'
import { cors } from 'hono/cors'
import type { OAuthStorage } from './storage.js'
import type {
  OAuthServerMetadata,
  OAuthResourceMetadata,
  OAuthClient,
  OAuthUser,
  TokenResponse,
  OAuthError,
  UpstreamOAuthConfig,
} from './types.js'
import {
  generateAuthorizationCode,
  generateToken,
  generateState,
  verifyCodeChallenge,
  hashClientSecret,
} from './pkce.js'
import {
  type DevModeConfig,
  type DevUser,
  type TestHelpers,
  createTestHelpers,
  generateLoginFormHtml,
} from './dev.js'

/**
 * Configuration for the OAuth 2.1 server
 */
export interface OAuth21ServerConfig {
  /** Server issuer URL (e.g., https://mcp.do) */
  issuer: string
  /** Storage backend for users, clients, tokens */
  storage: OAuthStorage
  /** Upstream OAuth provider configuration (optional if devMode enabled) */
  upstream?: UpstreamOAuthConfig
  /** Development mode configuration (no upstream provider needed) */
  devMode?: DevModeConfig
  /** Supported scopes */
  scopes?: string[]
  /** Access token lifetime in seconds (default: 3600) */
  accessTokenTtl?: number
  /** Refresh token lifetime in seconds (default: 2592000 = 30 days) */
  refreshTokenTtl?: number
  /** Authorization code lifetime in seconds (default: 600 = 10 minutes) */
  authCodeTtl?: number
  /** Enable dynamic client registration */
  enableDynamicRegistration?: boolean
  /** Callback after successful user authentication */
  onUserAuthenticated?: (user: OAuthUser) => void | Promise<void>
  /** Enable debug logging */
  debug?: boolean
}

/**
 * Extended Hono app with test helpers
 */
export interface OAuth21Server extends Hono {
  /** Test helpers for E2E testing (only available in devMode) */
  testHelpers?: TestHelpers
}

/**
 * Create an OAuth 2.1 server as a Hono app
 *
 * @example
 * ```typescript
 * import { createOAuth21Server, MemoryOAuthStorage } from '@dotdo/oauth'
 *
 * const oauthServer = createOAuth21Server({
 *   issuer: 'https://mcp.do',
 *   storage: new MemoryOAuthStorage(),
 *   upstream: {
 *     provider: 'workos',
 *     apiKey: env.WORKOS_API_KEY,
 *     clientId: env.WORKOS_CLIENT_ID,
 *   },
 * })
 *
 * // Mount on your main app
 * app.route('/', oauthServer)
 * ```
 *
 * @example Development mode (no upstream provider)
 * ```typescript
 * const oauthServer = createOAuth21Server({
 *   issuer: 'https://test.mcp.do',
 *   storage: new MemoryOAuthStorage(),
 *   devMode: {
 *     enabled: true,
 *     users: [
 *       { id: 'test-user', email: 'test@example.com', password: 'test123' }
 *     ],
 *     allowAnyCredentials: true, // Create users on the fly
 *   },
 * })
 *
 * // Access test helpers for Playwright
 * const { accessToken } = await oauthServer.testHelpers.getAccessToken('user-id', 'client-id')
 * ```
 */
export function createOAuth21Server(config: OAuth21ServerConfig): OAuth21Server {
  const {
    issuer,
    storage,
    upstream,
    devMode,
    scopes = ['openid', 'profile', 'email', 'offline_access'],
    accessTokenTtl = 3600,
    refreshTokenTtl = 2592000,
    authCodeTtl = 600,
    enableDynamicRegistration = true,
    onUserAuthenticated,
    debug = false,
  } = config

  // Validate configuration
  if (!devMode?.enabled && !upstream) {
    throw new Error('Either upstream configuration or devMode must be provided')
  }

  const app = new Hono() as OAuth21Server

  // Dev mode user storage
  const devUsers = new Map<string, DevUser>()

  // Initialize dev users
  if (devMode?.enabled && devMode.users) {
    for (const user of devMode.users) {
      devUsers.set(user.email.toLowerCase(), user)
    }
  }

  // Create test helpers if in dev mode
  if (devMode?.enabled) {
    app.testHelpers = createTestHelpers(storage, devUsers, {
      accessTokenTtl,
      refreshTokenTtl,
      authCodeTtl,
      allowAnyCredentials: devMode.allowAnyCredentials,
    })
  }

  // CORS for all endpoints
  app.use('*', cors({
    origin: '*',
    allowMethods: ['GET', 'POST', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization'],
    exposeHeaders: ['WWW-Authenticate'],
  }))

  // ═══════════════════════════════════════════════════════════════════════════
  // Well-Known Endpoints
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * OAuth 2.1 Authorization Server Metadata (RFC 8414)
   */
  app.get('/.well-known/oauth-authorization-server', (c) => {
    const metadata: OAuthServerMetadata = {
      issuer,
      authorization_endpoint: `${issuer}/authorize`,
      token_endpoint: `${issuer}/token`,
      registration_endpoint: enableDynamicRegistration ? `${issuer}/register` : undefined,
      revocation_endpoint: `${issuer}/revoke`,
      scopes_supported: scopes,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'client_secret_post'],
      code_challenge_methods_supported: ['S256'],
    }

    return c.json(metadata)
  })

  /**
   * OAuth 2.1 Protected Resource Metadata
   */
  app.get('/.well-known/oauth-protected-resource', (c) => {
    const metadata: OAuthResourceMetadata = {
      resource: issuer,
      authorization_servers: [issuer],
      scopes_supported: scopes,
      bearer_methods_supported: ['header'],
    }

    return c.json(metadata)
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Authorization Endpoint
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Authorization endpoint - starts the OAuth flow
   *
   * Required parameters:
   * - response_type: must be 'code'
   * - client_id: registered client ID
   * - redirect_uri: must match registered URI
   * - code_challenge: PKCE code challenge
   * - code_challenge_method: must be 'S256'
   *
   * Optional:
   * - scope: requested scopes
   * - state: CSRF protection
   */
  app.get('/authorize', async (c) => {
    const params = c.req.query()

    // Validate required parameters
    const clientId = params.client_id
    const redirectUri = params.redirect_uri
    const responseType = params.response_type
    const codeChallenge = params.code_challenge
    const codeChallengeMethod = params.code_challenge_method
    const scope = params.scope
    const state = params.state

    if (debug) {
      console.log('[OAuth] Authorize request:', { clientId, redirectUri, responseType, scope })
    }

    // Validate response_type
    if (responseType !== 'code') {
      return c.json({ error: 'unsupported_response_type', error_description: 'Only code response type is supported' } as OAuthError, 400)
    }

    // Validate client
    if (!clientId) {
      return c.json({ error: 'invalid_request', error_description: 'client_id is required' } as OAuthError, 400)
    }

    const client = await storage.getClient(clientId)
    if (!client) {
      return c.json({ error: 'invalid_client', error_description: 'Client not found' } as OAuthError, 400)
    }

    // Validate redirect_uri
    if (!redirectUri) {
      return c.json({ error: 'invalid_request', error_description: 'redirect_uri is required' } as OAuthError, 400)
    }

    if (!client.redirectUris.includes(redirectUri)) {
      return c.json({ error: 'invalid_request', error_description: 'redirect_uri not registered for this client' } as OAuthError, 400)
    }

    // Validate PKCE (required in OAuth 2.1)
    if (!codeChallenge) {
      return redirectWithError(redirectUri, 'invalid_request', 'code_challenge is required for OAuth 2.1', state)
    }

    if (codeChallengeMethod !== 'S256') {
      return redirectWithError(redirectUri, 'invalid_request', 'code_challenge_method must be S256', state)
    }

    // Dev mode: show login form instead of redirecting to upstream
    if (devMode?.enabled) {
      const html = devMode.customLoginPage || generateLoginFormHtml({
        issuer,
        clientId,
        redirectUri,
        scope,
        state,
        codeChallenge,
        codeChallengeMethod,
      })
      return c.html(html)
    }

    // Production mode: redirect to upstream
    if (!upstream) {
      return c.json({ error: 'server_error', error_description: 'No upstream provider configured' } as OAuthError, 500)
    }

    // Store the authorization request and redirect to upstream
    const upstreamState = generateState(64)

    // Store pending auth as a temporary authorization code that will be replaced
    await storage.saveAuthorizationCode({
      code: `pending:${upstreamState}`,
      clientId,
      userId: '', // Will be filled after upstream auth
      redirectUri,
      scope,
      codeChallenge,
      codeChallengeMethod: 'S256',
      state,
      issuedAt: Date.now(),
      expiresAt: Date.now() + authCodeTtl * 1000,
    })

    // Build upstream authorization URL
    const upstreamAuthUrl = buildUpstreamAuthUrl(upstream, {
      redirectUri: `${issuer}/callback`,
      state: upstreamState,
      scope: scope || 'openid profile email',
    })

    if (debug) {
      console.log('[OAuth] Redirecting to upstream:', upstreamAuthUrl)
    }

    return c.redirect(upstreamAuthUrl)
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Dev Mode Login Endpoint
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Login form submission (dev mode only)
   */
  app.post('/login', async (c) => {
    if (!devMode?.enabled) {
      return c.json({ error: 'invalid_request', error_description: 'Dev mode is not enabled' } as OAuthError, 400)
    }

    const formData = await c.req.parseBody()
    const email = String(formData.email || '')
    const password = String(formData.password || '')
    const clientId = String(formData.client_id || '')
    const redirectUri = String(formData.redirect_uri || '')
    const scope = String(formData.scope || '')
    const state = String(formData.state || '')
    const codeChallenge = String(formData.code_challenge || '')
    const codeChallengeMethod = String(formData.code_challenge_method || 'S256')

    if (debug) {
      console.log('[OAuth] Dev login attempt:', { email, clientId })
    }

    // Validate credentials
    const devUser = await app.testHelpers!.validateCredentials(email, password)
    if (!devUser) {
      const html = generateLoginFormHtml({
        issuer,
        clientId,
        redirectUri,
        scope,
        state,
        codeChallenge,
        codeChallengeMethod,
        error: 'Invalid email or password',
      })
      return c.html(html, 401)
    }

    // Get or create user in storage
    let user = await storage.getUserByEmail(devUser.email)
    if (!user) {
      user = {
        id: devUser.id,
        email: devUser.email,
        name: devUser.name,
        organizationId: devUser.organizationId,
        roles: devUser.roles,
        createdAt: Date.now(),
        updatedAt: Date.now(),
        lastLoginAt: Date.now(),
      }
      await storage.saveUser(user)
    } else {
      user.lastLoginAt = Date.now()
      user.updatedAt = Date.now()
      await storage.saveUser(user)
    }

    await onUserAuthenticated?.(user)

    // Generate authorization code
    const authCode = generateAuthorizationCode()

    await storage.saveAuthorizationCode({
      code: authCode,
      clientId,
      userId: user.id,
      redirectUri,
      scope,
      codeChallenge,
      codeChallengeMethod: 'S256',
      state,
      issuedAt: Date.now(),
      expiresAt: Date.now() + authCodeTtl * 1000,
    })

    // Redirect back to client with code
    const redirectUrl = new URL(redirectUri)
    redirectUrl.searchParams.set('code', authCode)
    if (state) {
      redirectUrl.searchParams.set('state', state)
    }

    if (debug) {
      console.log('[OAuth] Dev login successful, redirecting to:', redirectUrl.toString())
    }

    return c.redirect(redirectUrl.toString())
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Upstream OAuth Callback
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Callback from upstream OAuth provider
   */
  app.get('/callback', async (c) => {
    const code = c.req.query('code')
    const upstreamState = c.req.query('state')
    const error = c.req.query('error')
    const errorDescription = c.req.query('error_description')

    if (debug) {
      console.log('[OAuth] Callback received:', { code: !!code, state: upstreamState, error })
    }

    if (error) {
      // Retrieve pending auth to get redirect_uri
      const pendingAuth = await storage.consumeAuthorizationCode(`pending:${upstreamState}`)
      if (pendingAuth) {
        return redirectWithError(pendingAuth.redirectUri, error, errorDescription, pendingAuth.state)
      }
      return c.json({ error, error_description: errorDescription } as OAuthError, 400)
    }

    if (!code || !upstreamState) {
      return c.json({ error: 'invalid_request', error_description: 'Missing code or state' } as OAuthError, 400)
    }

    // Retrieve pending authorization
    const pendingAuth = await storage.consumeAuthorizationCode(`pending:${upstreamState}`)
    if (!pendingAuth) {
      return c.json({ error: 'invalid_request', error_description: 'Invalid or expired state' } as OAuthError, 400)
    }

    // In dev mode, callback shouldn't be used (login handles it directly)
    if (!upstream) {
      return c.json({ error: 'server_error', error_description: 'No upstream provider configured' } as OAuthError, 500)
    }

    try {
      // Exchange code with upstream provider
      const upstreamTokens = await exchangeUpstreamCode(upstream, code, `${issuer}/callback`)

      if (debug) {
        console.log('[OAuth] Upstream tokens received:', { hasAccessToken: !!upstreamTokens.access_token })
      }

      // Get or create user
      const user = await getOrCreateUser(storage, upstreamTokens.user, onUserAuthenticated)

      // Generate our own authorization code
      const authCode = generateAuthorizationCode()

      await storage.saveAuthorizationCode({
        code: authCode,
        clientId: pendingAuth.clientId,
        userId: user.id,
        redirectUri: pendingAuth.redirectUri,
        scope: pendingAuth.scope,
        codeChallenge: pendingAuth.codeChallenge,
        codeChallengeMethod: 'S256',
        state: pendingAuth.state,
        issuedAt: Date.now(),
        expiresAt: Date.now() + authCodeTtl * 1000,
      })

      // Redirect back to client with our code
      const redirectUrl = new URL(pendingAuth.redirectUri)
      redirectUrl.searchParams.set('code', authCode)
      if (pendingAuth.state) {
        redirectUrl.searchParams.set('state', pendingAuth.state)
      }

      if (debug) {
        console.log('[OAuth] Redirecting to client:', redirectUrl.toString())
      }

      return c.redirect(redirectUrl.toString())
    } catch (err) {
      if (debug) {
        console.error('[OAuth] Callback error:', err)
      }
      return redirectWithError(
        pendingAuth.redirectUri,
        'server_error',
        err instanceof Error ? err.message : 'Authentication failed',
        pendingAuth.state
      )
    }
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Token Endpoint
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Token endpoint - exchanges authorization code for tokens
   */
  app.post('/token', async (c) => {
    const contentType = c.req.header('content-type')
    let params: Record<string, string>

    if (contentType?.includes('application/json')) {
      params = await c.req.json()
    } else {
      const formData = await c.req.parseBody()
      params = Object.fromEntries(
        Object.entries(formData).map(([k, v]) => [k, String(v)])
      )
    }

    const grantType = params.grant_type

    if (debug) {
      console.log('[OAuth] Token request:', { grantType, clientId: params.client_id })
    }

    if (grantType === 'authorization_code') {
      return handleAuthorizationCodeGrant(c, params, storage, accessTokenTtl, refreshTokenTtl, debug)
    } else if (grantType === 'refresh_token') {
      return handleRefreshTokenGrant(c, params, storage, accessTokenTtl, refreshTokenTtl, debug)
    } else {
      return c.json({ error: 'unsupported_grant_type', error_description: 'Only authorization_code and refresh_token grants are supported' } as OAuthError, 400)
    }
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Dynamic Client Registration
  // ═══════════════════════════════════════════════════════════════════════════

  if (enableDynamicRegistration) {
    /**
     * Client registration endpoint (RFC 7591)
     */
    app.post('/register', async (c) => {
      const body = await c.req.json<{
        client_name: string
        redirect_uris: string[]
        grant_types?: string[]
        response_types?: string[]
        token_endpoint_auth_method?: string
        scope?: string
      }>()

      if (debug) {
        console.log('[OAuth] Client registration:', body)
      }

      if (!body.client_name) {
        return c.json({ error: 'invalid_client_metadata', error_description: 'client_name is required' } as OAuthError, 400)
      }

      if (!body.redirect_uris || body.redirect_uris.length === 0) {
        return c.json({ error: 'invalid_client_metadata', error_description: 'redirect_uris is required' } as OAuthError, 400)
      }

      // Generate client credentials
      const clientId = `client_${generateToken(24)}`
      const clientSecret = generateToken(48)
      const clientSecretHash = await hashClientSecret(clientSecret)

      const client: OAuthClient = {
        clientId,
        clientSecretHash,
        clientName: body.client_name,
        redirectUris: body.redirect_uris,
        grantTypes: (body.grant_types as OAuthClient['grantTypes']) || ['authorization_code', 'refresh_token'],
        responseTypes: (body.response_types as OAuthClient['responseTypes']) || ['code'],
        tokenEndpointAuthMethod: (body.token_endpoint_auth_method as OAuthClient['tokenEndpointAuthMethod']) || 'client_secret_basic',
        scope: body.scope,
        createdAt: Date.now(),
      }

      await storage.saveClient(client)

      // Return client credentials (secret is only shown once)
      return c.json({
        client_id: clientId,
        client_secret: clientSecret,
        client_id_issued_at: Math.floor(client.createdAt / 1000),
        client_secret_expires_at: 0, // Never expires
        client_name: client.clientName,
        redirect_uris: client.redirectUris,
        grant_types: client.grantTypes,
        response_types: client.responseTypes,
        token_endpoint_auth_method: client.tokenEndpointAuthMethod,
        scope: client.scope,
      }, 201)
    })
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Token Revocation
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Token revocation endpoint (RFC 7009)
   */
  app.post('/revoke', async (c) => {
    const formData = await c.req.parseBody()
    const token = String(formData.token || '')
    const tokenTypeHint = String(formData.token_type_hint || '')

    if (!token) {
      return c.json({ error: 'invalid_request', error_description: 'token is required' } as OAuthError, 400)
    }

    // Try to revoke as access token first
    if (tokenTypeHint !== 'refresh_token') {
      await storage.revokeAccessToken(token)
    }

    // Then try as refresh token
    if (tokenTypeHint !== 'access_token') {
      await storage.revokeRefreshToken(token)
    }

    // RFC 7009 says to return 200 OK even if token was invalid
    return c.json({ success: true })
  })

  return app
}

// ═══════════════════════════════════════════════════════════════════════════
// Helper Functions
// ═══════════════════════════════════════════════════════════════════════════

function redirectWithError(redirectUri: string, error: string, description?: string, state?: string): Response {
  const url = new URL(redirectUri)
  url.searchParams.set('error', error)
  if (description) {
    url.searchParams.set('error_description', description)
  }
  if (state) {
    url.searchParams.set('state', state)
  }
  return Response.redirect(url.toString(), 302)
}

function buildUpstreamAuthUrl(
  upstream: UpstreamOAuthConfig,
  params: { redirectUri: string; state: string; scope: string }
): string {
  if (upstream.provider === 'workos') {
    const url = new URL('https://api.workos.com/user_management/authorize')
    url.searchParams.set('client_id', upstream.clientId)
    url.searchParams.set('redirect_uri', params.redirectUri)
    url.searchParams.set('response_type', 'code')
    url.searchParams.set('state', params.state)
    url.searchParams.set('provider', 'authkit')
    return url.toString()
  }

  // Custom provider
  if (!upstream.authorizationEndpoint) {
    throw new Error('authorizationEndpoint is required for custom providers')
  }

  const url = new URL(upstream.authorizationEndpoint)
  url.searchParams.set('client_id', upstream.clientId)
  url.searchParams.set('redirect_uri', params.redirectUri)
  url.searchParams.set('response_type', 'code')
  url.searchParams.set('state', params.state)
  url.searchParams.set('scope', params.scope)
  return url.toString()
}

async function exchangeUpstreamCode(
  upstream: UpstreamOAuthConfig,
  code: string,
  redirectUri: string
): Promise<{
  access_token: string
  refresh_token?: string
  expires_in?: number
  user: {
    id: string
    email: string
    first_name?: string
    last_name?: string
    organization_id?: string
  }
}> {
  if (upstream.provider === 'workos') {
    const response = await fetch('https://api.workos.com/user_management/authenticate', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Bearer ${upstream.apiKey}`,
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: upstream.clientId,
        code,
        redirect_uri: redirectUri,
      }).toString(),
    })

    if (!response.ok) {
      const error = await response.text()
      throw new Error(`WorkOS authentication failed: ${response.status} - ${error}`)
    }

    return response.json()
  }

  // Custom provider
  if (!upstream.tokenEndpoint) {
    throw new Error('tokenEndpoint is required for custom providers')
  }

  const response = await fetch(upstream.tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: upstream.clientId,
      client_secret: upstream.apiKey,
      code,
      redirect_uri: redirectUri,
    }).toString(),
  })

  if (!response.ok) {
    const error = await response.text()
    throw new Error(`Token exchange failed: ${response.status} - ${error}`)
  }

  return response.json()
}

async function getOrCreateUser(
  storage: OAuthStorage,
  upstreamUser: { id: string; email: string; first_name?: string; last_name?: string; organization_id?: string },
  onUserAuthenticated?: (user: OAuthUser) => void | Promise<void>
): Promise<OAuthUser> {
  // Try to find existing user by email
  let user = await storage.getUserByEmail(upstreamUser.email)

  if (!user) {
    // Create new user
    user = {
      id: upstreamUser.id,
      email: upstreamUser.email,
      name: [upstreamUser.first_name, upstreamUser.last_name].filter(Boolean).join(' ') || undefined,
      organizationId: upstreamUser.organization_id,
      createdAt: Date.now(),
      updatedAt: Date.now(),
      lastLoginAt: Date.now(),
    }
    await storage.saveUser(user)
  } else {
    // Update last login
    user.lastLoginAt = Date.now()
    user.updatedAt = Date.now()
    await storage.saveUser(user)
  }

  await onUserAuthenticated?.(user)

  return user
}

async function handleAuthorizationCodeGrant(
  c: any,
  params: Record<string, string>,
  storage: OAuthStorage,
  accessTokenTtl: number,
  refreshTokenTtl: number,
  debug: boolean
): Promise<Response> {
  const { code, client_id, redirect_uri, code_verifier } = params

  if (!code) {
    return c.json({ error: 'invalid_request', error_description: 'code is required' } as OAuthError, 400)
  }

  if (!client_id) {
    return c.json({ error: 'invalid_request', error_description: 'client_id is required' } as OAuthError, 400)
  }

  // Consume authorization code (one-time use)
  const authCode = await storage.consumeAuthorizationCode(code)
  if (!authCode) {
    return c.json({ error: 'invalid_grant', error_description: 'Invalid or expired authorization code' } as OAuthError, 400)
  }

  // Verify client
  if (authCode.clientId !== client_id) {
    return c.json({ error: 'invalid_grant', error_description: 'Client mismatch' } as OAuthError, 400)
  }

  // Verify redirect_uri
  if (redirect_uri && authCode.redirectUri !== redirect_uri) {
    return c.json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' } as OAuthError, 400)
  }

  // Verify PKCE
  if (authCode.codeChallenge) {
    if (!code_verifier) {
      return c.json({ error: 'invalid_request', error_description: 'code_verifier is required' } as OAuthError, 400)
    }

    const valid = await verifyCodeChallenge(code_verifier, authCode.codeChallenge, authCode.codeChallengeMethod || 'S256')
    if (!valid) {
      return c.json({ error: 'invalid_grant', error_description: 'Invalid code_verifier' } as OAuthError, 400)
    }
  }

  // Check expiration
  if (Date.now() > authCode.expiresAt) {
    return c.json({ error: 'invalid_grant', error_description: 'Authorization code expired' } as OAuthError, 400)
  }

  // Generate tokens
  const accessToken = generateToken(48)
  const refreshToken = generateToken(64)
  const now = Date.now()

  await storage.saveAccessToken({
    token: accessToken,
    tokenType: 'Bearer',
    clientId: authCode.clientId,
    userId: authCode.userId,
    scope: authCode.scope,
    issuedAt: now,
    expiresAt: now + accessTokenTtl * 1000,
  })

  await storage.saveRefreshToken({
    token: refreshToken,
    clientId: authCode.clientId,
    userId: authCode.userId,
    scope: authCode.scope,
    issuedAt: now,
    expiresAt: refreshTokenTtl > 0 ? now + refreshTokenTtl * 1000 : undefined,
  })

  // Save grant
  await storage.saveGrant({
    id: `${authCode.userId}:${authCode.clientId}`,
    userId: authCode.userId,
    clientId: authCode.clientId,
    scope: authCode.scope,
    createdAt: now,
    lastUsedAt: now,
  })

  if (debug) {
    console.log('[OAuth] Tokens issued for user:', authCode.userId)
  }

  const response: TokenResponse = {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: accessTokenTtl,
    refresh_token: refreshToken,
    scope: authCode.scope,
  }

  return c.json(response)
}

async function handleRefreshTokenGrant(
  c: any,
  params: Record<string, string>,
  storage: OAuthStorage,
  accessTokenTtl: number,
  refreshTokenTtl: number,
  debug: boolean
): Promise<Response> {
  const { refresh_token, client_id } = params

  if (!refresh_token) {
    return c.json({ error: 'invalid_request', error_description: 'refresh_token is required' } as OAuthError, 400)
  }

  const storedRefresh = await storage.getRefreshToken(refresh_token)
  if (!storedRefresh) {
    return c.json({ error: 'invalid_grant', error_description: 'Invalid refresh token' } as OAuthError, 400)
  }

  if (storedRefresh.revoked) {
    return c.json({ error: 'invalid_grant', error_description: 'Refresh token has been revoked' } as OAuthError, 400)
  }

  if (storedRefresh.expiresAt && Date.now() > storedRefresh.expiresAt) {
    return c.json({ error: 'invalid_grant', error_description: 'Refresh token expired' } as OAuthError, 400)
  }

  if (client_id && storedRefresh.clientId !== client_id) {
    return c.json({ error: 'invalid_grant', error_description: 'Client mismatch' } as OAuthError, 400)
  }

  // Generate new tokens
  const accessToken = generateToken(48)
  const newRefreshToken = generateToken(64)
  const now = Date.now()

  await storage.saveAccessToken({
    token: accessToken,
    tokenType: 'Bearer',
    clientId: storedRefresh.clientId,
    userId: storedRefresh.userId,
    scope: storedRefresh.scope,
    issuedAt: now,
    expiresAt: now + accessTokenTtl * 1000,
  })

  // Rotate refresh token
  await storage.revokeRefreshToken(refresh_token)
  await storage.saveRefreshToken({
    token: newRefreshToken,
    clientId: storedRefresh.clientId,
    userId: storedRefresh.userId,
    scope: storedRefresh.scope,
    issuedAt: now,
    expiresAt: refreshTokenTtl > 0 ? now + refreshTokenTtl * 1000 : undefined,
  })

  // Update grant last used
  const grant = await storage.getGrant(storedRefresh.userId, storedRefresh.clientId)
  if (grant) {
    grant.lastUsedAt = now
    await storage.saveGrant(grant)
  }

  if (debug) {
    console.log('[OAuth] Tokens refreshed for user:', storedRefresh.userId)
  }

  const response: TokenResponse = {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: accessTokenTtl,
    refresh_token: newRefreshToken,
    scope: storedRefresh.scope,
  }

  return c.json(response)
}

// ═══════════════════════════════════════════════════════════════════════════
// JWT Verification Re-exports
// ═══════════════════════════════════════════════════════════════════════════

// Re-export JWT verification utilities for downstream consumers
export { verifyJWT, decodeJWT, isJWTExpired, clearJWKSCache } from './jwt.js'
export type { JWTVerifyResult, JWTVerifyOptions, JWTPayload, JWTHeader } from './jwt.js'
