/**
 * @dotdo/oauth - OAuth 2.1 Server Implementation
 *
 * Creates a Hono app that implements OAuth 2.1 authorization server endpoints:
 * - /.well-known/oauth-authorization-server (RFC 8414)
 * - /.well-known/oauth-protected-resource (draft-ietf-oauth-resource-metadata)
 * - /.well-known/jwks.json (JWKS endpoint)
 * - /authorize (authorization endpoint)
 * - /callback (upstream OAuth callback)
 * - /token (token endpoint)
 * - /introspect (token introspection - RFC 7662)
 * - /register (dynamic client registration - RFC 7591)
 * - /userinfo (OpenID Connect UserInfo)
 * - /revoke (token revocation - RFC 7009)
 *
 * This server acts as a federated OAuth 2.1 server:
 * - It is an OAuth SERVER to downstream clients (Claude, ChatGPT, etc.)
 * - It is an OAuth CLIENT to upstream providers (WorkOS, Auth0, etc.)
 */

import { Hono } from 'hono'
import type { Context } from 'hono'
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
  verifyClientSecret,
} from './pkce.js'
import {
  type DevModeConfig,
  type DevUser,
  type TestHelpers,
  createTestHelpers,
  generateLoginFormHtml,
} from './dev.js'
import type { SigningKeyManager, AccessTokenClaims } from './jwt-signing.js'
import { verifyJWTWithKeyManager } from './jwt-signing.js'
import { decodeJWT, verifyJWT } from './jwt.js'

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
  /** Allowed CORS origins (default: issuer origin only in production, '*' in dev mode) */
  allowedOrigins?: string[]
  /**
   * Signing key manager for JWT access tokens (optional)
   * If provided, access tokens will be signed JWTs instead of opaque tokens.
   * This enables the JWKS and introspection endpoints.
   */
  signingKeyManager?: SigningKeyManager
  /**
   * Use JWT access tokens instead of opaque tokens (default: false)
   * Requires signingKeyManager to be set, or will auto-create one in memory.
   */
  useJwtAccessTokens?: boolean
  /**
   * Trusted issuers for X-Issuer header validation (optional).
   * If set, only X-Issuer values in this list will be accepted.
   * If not set, any valid URL is accepted (backwards compatible).
   */
  trustedIssuers?: string[]
  /**
   * Require authentication for dynamic client registration (optional)
   * If true, registration endpoint requires either an admin token or valid Bearer token
   */
  requireRegistrationAuth?: boolean
  /**
   * Admin token for client registration (optional)
   * If set, clients can provide this token via x-admin-token header to register
   */
  adminToken?: string
}

/**
 * Extended Hono app with test helpers and signing key manager
 */
export interface OAuth21Server extends Hono {
  /** Test helpers for E2E testing (only available in devMode) */
  testHelpers?: TestHelpers
  /** Signing key manager (available if useJwtAccessTokens is enabled) */
  signingKeyManager?: SigningKeyManager
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
    issuer: defaultIssuer,
    storage,
    upstream,
    devMode,
    scopes = ['openid', 'profile', 'email', 'offline_access'],
    accessTokenTtl = 3600, // 1 hour
    refreshTokenTtl = 2592000,
    authCodeTtl = 600,
    enableDynamicRegistration = true,
    onUserAuthenticated,
    debug = false,
    allowedOrigins,
    signingKeyManager: providedSigningKeyManager,
    useJwtAccessTokens = false,
    trustedIssuers,
    requireRegistrationAuth = false,
    adminToken,
  } = config

  /**
   * Get the effective issuer for a request.
   * Supports dynamic issuers via X-Issuer header for multi-tenant scenarios.
   * This allows services like collections.do to proxy OAuth and have tokens
   * issued with their own domain as the issuer.
   */
  function getEffectiveIssuer(c: Context): string {
    const xIssuer = c.req.header('X-Issuer')
    if (xIssuer) {
      // Validate it's a proper URL
      try {
        new URL(xIssuer)
        const normalized = xIssuer.replace(/\/$/, '') // Remove trailing slash
        // If trustedIssuers is configured, only accept values in the list
        if (trustedIssuers) {
          if (!trustedIssuers.includes(normalized)) {
            if (debug) {
              console.warn('[OAuth] X-Issuer not in trustedIssuers list:', normalized)
            }
            return defaultIssuer
          }
        }
        return normalized
      } catch {
        if (debug) {
          console.warn('[OAuth] Invalid X-Issuer header:', xIssuer)
        }
      }
    }
    return defaultIssuer
  }

  // Validate configuration
  if (!devMode?.enabled && !upstream) {
    throw new Error('Either upstream configuration or devMode must be provided')
  }

  // Security warning: devMode should never be used in production
  // Use globalThis to access process in a way that works in all environments (Node, Deno, browsers)
  const nodeEnv = (globalThis as { process?: { env?: { NODE_ENV?: string } } }).process?.env?.NODE_ENV
  if (devMode?.enabled && nodeEnv === 'production') {
    console.warn(
      '[OAuth] WARNING: devMode is enabled in a production environment!\n' +
      'This bypasses upstream OAuth security and allows simple password authentication.\n' +
      'This is a critical security risk. Set devMode.enabled = false for production.'
    )
  }

  const app = new Hono() as OAuth21Server

  // Signing key manager for JWT access tokens
  // If useJwtAccessTokens is enabled but no manager provided, we'll create keys lazily
  let signingKeyManager = providedSigningKeyManager

  // Helper to get or create signing key
  async function ensureSigningKey(): Promise<{
    kid: string
    alg: 'RS256'
    privateKey: CryptoKey
    publicKey: CryptoKey
    createdAt: number
  }> {
    if (!signingKeyManager) {
      // Create an in-memory key manager lazily
      const { SigningKeyManager: SKM } = await import('./jwt-signing.js')
      signingKeyManager = new SKM()
      app.signingKeyManager = signingKeyManager
    }
    return signingKeyManager.getCurrentKey()
  }

  /**
   * Validate and filter requested scopes against the server's configured scopes.
   * Returns only the scopes that are allowed, or undefined if no valid scopes.
   */
  function validateScopes(requestedScope: string | undefined): string | undefined {
    if (!requestedScope) return undefined
    const requested = requestedScope.split(/\s+/).filter(Boolean)
    const allowed = requested.filter((s) => scopes.includes(s))
    return allowed.length > 0 ? allowed.join(' ') : undefined
  }

  // Helper to generate JWT access token for simple login flow
  // Accepts optional issuer override for multi-tenant scenarios
  async function generateAccessToken(user: OAuthUser, clientId: string, scope: string, issuerOverride?: string): Promise<string> {
    const { signAccessToken } = await import('./jwt-signing.js')
    const key = await ensureSigningKey()
    return signAccessToken(key, {
      sub: user.id,
      client_id: clientId,
      scope,
      email: user.email,
      name: user.name,
      // Include RBAC claims from user
      ...(user.organizationId && { org_id: user.organizationId }),
      ...(user.roles && user.roles.length > 0 && { roles: user.roles }),
      ...(user.permissions && user.permissions.length > 0 && { permissions: user.permissions }),
    }, {
      issuer: issuerOverride || defaultIssuer,
      audience: clientId,
      expiresIn: accessTokenTtl,
    })
  }

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
      ...(devMode.allowAnyCredentials !== undefined && { allowAnyCredentials: devMode.allowAnyCredentials }),
    })
  }

  // Attach signing key manager if provided
  if (providedSigningKeyManager) {
    app.signingKeyManager = providedSigningKeyManager
  }

  // CORS for all endpoints - restrictive by default
  // In production, only allow issuer origin unless explicitly configured
  // In dev mode, allow all origins if not specified
  const corsOrigins = allowedOrigins ?? (devMode?.enabled ? ['*'] : [new URL(defaultIssuer).origin])
  app.use('*', cors({
    origin: (origin) => {
      // If '*' is in the list, allow all origins
      if (corsOrigins.includes('*')) {
        return origin || '*'
      }
      // Otherwise, check if the origin is in the allowed list
      if (origin && corsOrigins.includes(origin)) {
        return origin
      }
      // Return null to deny the request
      return null
    },
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
    const issuer = getEffectiveIssuer(c)
    const metadata = {
      issuer,
      authorization_endpoint: `${issuer}/authorize`,
      token_endpoint: `${issuer}/token`,
      ...(enableDynamicRegistration && { registration_endpoint: `${issuer}/register` }),
      revocation_endpoint: `${issuer}/revoke`,
      // JWKS and introspection endpoints (always advertised, but JWKS only works if signing keys available)
      jwks_uri: `${issuer}/.well-known/jwks.json`,
      introspection_endpoint: `${issuer}/introspect`,
      userinfo_endpoint: `${issuer}/userinfo`,
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
    const issuer = getEffectiveIssuer(c)
    const metadata: OAuthResourceMetadata = {
      resource: issuer,
      authorization_servers: [issuer],
      scopes_supported: scopes,
      bearer_methods_supported: ['header'],
    }

    return c.json(metadata)
  })

  /**
   * JWKS endpoint - exposes public signing keys
   */
  app.get('/.well-known/jwks.json', async (c) => {
    try {
      if (!signingKeyManager && !useJwtAccessTokens) {
        // No signing keys configured - return empty JWKS
        return c.json({ keys: [] })
      }

      // Ensure signing key manager is initialized
      await ensureSigningKey()
      // Export ALL keys (current + rotated) so tokens signed with older keys can still be verified
      const jwks = await signingKeyManager!.toJWKS()
      return c.json(jwks)
    } catch (err) {
      if (debug) {
        console.error('[OAuth] JWKS error:', err)
      }
      return c.json({ keys: [] })
    }
  })

  /**
   * Token Introspection endpoint (RFC 7662)
   * Allows resource servers to validate tokens
   */
  app.post('/introspect', async (c) => {
    const contentType = c.req.header('content-type')
    let token: string | undefined

    if (contentType?.includes('application/json')) {
      const body = await c.req.json<{ token?: string }>()
      token = body.token
    } else {
      const formData = await c.req.parseBody()
      token = String(formData['token'] || '')
    }

    if (!token) {
      return c.json({ active: false })
    }

    // Try to decode as JWT first
    const decoded = decodeJWT(token)
    if (decoded) {
      // It's a JWT - verify signature and claims using verifyJWTWithKeyManager
      const effectiveIssuer = getEffectiveIssuer(c)

      if (!signingKeyManager && !useJwtAccessTokens) {
        return c.json({ active: false })
      }

      // Ensure signing key manager is initialized
      await ensureSigningKey()

      // Verify signature and exp using the key manager (no issuer - we check manually for multi-issuer support)
      const payload = await verifyJWTWithKeyManager(token, signingKeyManager!)
      if (!payload) {
        return c.json({ active: false })
      }

      // Check issuer - accept tokens from any issuer we could have issued
      if (payload.iss && payload.iss !== effectiveIssuer && payload.iss !== defaultIssuer) {
        return c.json({ active: false })
      }

      return c.json({
        active: true,
        sub: payload.sub,
        client_id: payload.client_id,
        scope: payload.scope,
        exp: payload.exp,
        iat: payload.iat,
        iss: payload.iss,
        token_type: 'Bearer',
      })
    }

    // Not a JWT - check opaque token storage
    const storedToken = await storage.getAccessToken(token)
    if (!storedToken) {
      return c.json({ active: false })
    }

    // Check expiration
    if (Date.now() > storedToken.expiresAt) {
      return c.json({ active: false })
    }

    return c.json({
      active: true,
      sub: storedToken.userId,
      client_id: storedToken.clientId,
      scope: storedToken.scope,
      exp: Math.floor(storedToken.expiresAt / 1000),
      iat: Math.floor(storedToken.issuedAt / 1000),
      token_type: storedToken.tokenType,
    })
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

    // Validate required parameters (bracket notation for index signature access)
    const clientId = params['client_id']
    const redirectUri = params['redirect_uri']
    const responseType = params['response_type']
    const codeChallenge = params['code_challenge']
    const codeChallengeMethod = params['code_challenge_method']
    const scope = params['scope']
    const state = params['state']

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

    // Validate redirect_uri is a valid URL
    try {
      new URL(redirectUri)
    } catch {
      return c.json({ error: 'invalid_request', error_description: 'redirect_uri must be a valid URL' } as OAuthError, 400)
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

    // Validate requested scopes against server's configured scopes
    const grantedScope = validateScopes(scope)
    if (scope && !grantedScope) {
      return redirectWithError(redirectUri, 'invalid_scope', 'None of the requested scopes are supported', state)
    }

    // Dev mode: show login form instead of redirecting to upstream
    if (devMode?.enabled) {
      const effectiveIssuer = getEffectiveIssuer(c)
      const html = devMode.customLoginPage || generateLoginFormHtml({
        issuer: effectiveIssuer,
        clientId,
        redirectUri,
        ...(grantedScope !== undefined && { scope: grantedScope }),
        ...(state !== undefined && { state }),
        codeChallenge,
        codeChallengeMethod,
      })
      return c.html(html)
    }

    // Production mode: redirect to upstream
    if (!upstream) {
      return c.json({ error: 'server_error', error_description: 'No upstream provider configured' } as OAuthError, 500)
    }

    // Get effective issuer for multi-tenant support
    const effectiveIssuer = getEffectiveIssuer(c)

    // Store the authorization request and redirect to upstream
    // Generate a cryptographically secure state for CSRF protection with upstream provider
    const upstreamState = generateState(64)

    // Store pending auth as a temporary authorization code that will be replaced
    // The upstreamState is stored both in the code key (for lookup) and as a separate field (for explicit validation)
    // This provides defense-in-depth for CSRF protection
    await storage.saveAuthorizationCode({
      code: `pending:${upstreamState}`,
      clientId,
      userId: '', // Will be filled after upstream auth
      redirectUri,
      ...(grantedScope !== undefined && { scope: grantedScope }),
      codeChallenge,
      codeChallengeMethod: 'S256',
      ...(state !== undefined && { state }), // Client's state (will be passed back to client)
      upstreamState, // Server's state for explicit validation in callback
      effectiveIssuer, // Store for multi-tenant token generation
      issuedAt: Date.now(),
      expiresAt: Date.now() + authCodeTtl * 1000,
    })

    // Build upstream authorization URL
    // Note: The callback URL uses defaultIssuer (oauth.do) since that's what's registered with upstream providers
    // The effectiveIssuer is stored in the auth code and used when generating tokens
    // Use /api/callback to differentiate from SPA's client-side /callback route
    const upstreamAuthUrl = buildUpstreamAuthUrl(upstream, {
      redirectUri: `${defaultIssuer}/api/callback`,
      state: upstreamState,
      scope: grantedScope || 'openid profile email',
    })

    if (debug) {
      console.log('[OAuth] Redirecting to upstream:', upstreamAuthUrl)
    }

    return c.redirect(upstreamAuthUrl)
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Simple Login Endpoint (for first-party apps)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Simple login redirect for first-party apps
   *
   * This is a simplified flow that doesn't require the full OAuth ceremony.
   * It redirects to the upstream provider and returns a JWT to the return_to URL.
   *
   * Usage: GET /login?returnTo=https://myapp.com/callback
   * After auth, redirects to: https://myapp.com/callback?_token=<jwt>
   *
   * If returnTo is not provided, defaults to:
   * - Referer URL (if origin is in allowedOrigins)
   * - Issuer root otherwise
   */
  app.get('/login', async (c) => {
    // Support both camelCase (preferred) and snake_case for compatibility
    let returnTo = c.req.query('returnTo') || c.req.query('return_to')

    // Default to referer if it's an allowed origin
    if (!returnTo) {
      const referer = c.req.header('Referer')
      if (referer) {
        try {
          const refererUrl = new URL(referer)
          // Check if referer's origin is allowed (or if we allow all origins)
          const isAllowed = corsOrigins.includes('*') || corsOrigins.includes(refererUrl.origin)
          if (isAllowed) {
            returnTo = referer
          }
        } catch {
          // Invalid referer, ignore
        }
      }
      // Default to effective issuer root
      const effectiveIssuer = getEffectiveIssuer(c)
      if (!returnTo) {
        returnTo = effectiveIssuer
      }
    }

    // Validate return_to is a valid URL
    try {
      new URL(returnTo)
    } catch {
      return c.json({ error: 'invalid_request', error_description: 'return_to must be a valid URL' } as OAuthError, 400)
    }

    // Get effective issuer for token generation
    const effectiveIssuer = getEffectiveIssuer(c)

    // Dev mode: show a simple form or auto-login
    if (devMode?.enabled && devMode.users?.length) {
      // In dev mode, auto-login as the first user and redirect
      const devUser = devMode.users[0]!
      let user = await storage.getUserByEmail(devUser.email)
      if (!user) {
        user = {
          id: devUser.id,
          email: devUser.email,
          ...(devUser.name !== undefined && { name: devUser.name }),
          createdAt: Date.now(),
          updatedAt: Date.now(),
          lastLoginAt: Date.now(),
        }
        await storage.saveUser(user)
      }

      // Generate JWT access token with effective issuer
      const accessToken = await generateAccessToken(user, 'first-party', 'openid profile email', effectiveIssuer)

      // Redirect with token
      const url = new URL(returnTo)
      url.searchParams.set('_token', accessToken)
      return c.redirect(url.toString())
    }

    // Production mode: redirect to upstream
    if (!upstream) {
      return c.json({ error: 'server_error', error_description: 'No upstream provider configured' } as OAuthError, 500)
    }

    // Generate state to track this login request
    const loginState = generateState(64)

    // Store the return_to URL in the auth code table (reusing the structure)
    // Also store effective issuer for use when generating tokens in callback
    await storage.saveAuthorizationCode({
      code: `login:${loginState}`,
      clientId: 'first-party',
      userId: '',
      redirectUri: returnTo,
      effectiveIssuer, // Store for use in callback
      issuedAt: Date.now(),
      expiresAt: Date.now() + authCodeTtl * 1000,
    })

    // Build upstream authorization URL
    // Note: Callback URL uses defaultIssuer (oauth.do) since that's registered with upstream providers
    // Use /api/callback to differentiate from SPA's client-side /callback route
    const upstreamAuthUrl = buildUpstreamAuthUrl(upstream, {
      redirectUri: `${defaultIssuer}/api/callback`,
      state: loginState,
      scope: 'openid profile email',
    })

    if (debug) {
      console.log('[OAuth] Simple login redirect to upstream:', upstreamAuthUrl)
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
    const email = String(formData['email'] || '')
    const password = String(formData['password'] || '')
    const clientId = String(formData['client_id'] || '')
    const redirectUri = String(formData['redirect_uri'] || '')
    const scope = String(formData['scope'] || '')
    const state = String(formData['state'] || '')
    const codeChallenge = String(formData['code_challenge'] || '')
    const codeChallengeMethod = String(formData['code_challenge_method'] || 'S256')

    // Get effective issuer for multi-tenant support
    const effectiveIssuer = getEffectiveIssuer(c)

    if (debug) {
      console.log('[OAuth] Dev login attempt:', { email, clientId })
    }

    // Validate credentials
    if (!app.testHelpers) {
      return c.json({ error: 'server_error', error_description: 'Test helpers not available' } as OAuthError, 500)
    }
    const devUser = await app.testHelpers.validateCredentials(email, password)
    if (!devUser) {
      const html = generateLoginFormHtml({
        issuer: effectiveIssuer,
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
        ...(devUser.name !== undefined && { name: devUser.name }),
        ...(devUser.organizationId !== undefined && { organizationId: devUser.organizationId }),
        ...(devUser.roles !== undefined && { roles: devUser.roles }),
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

    if (onUserAuthenticated) {
      await onUserAuthenticated(user)
    }

    // Validate and filter scopes
    const grantedScope = validateScopes(scope)

    // Generate authorization code
    const authCode = generateAuthorizationCode()

    await storage.saveAuthorizationCode({
      code: authCode,
      clientId,
      userId: user.id,
      redirectUri,
      ...(grantedScope && { scope: grantedScope }),
      codeChallenge,
      codeChallengeMethod: 'S256',
      ...(state && { state }),
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
   * Callback from upstream OAuth provider (server-side flow)
   * Note: /callback (without /api) is handled by the SPA for client-side WorkOS AuthKit
   */
  app.get('/api/callback', async (c) => {
    const code = c.req.query('code')
    const upstreamState = c.req.query('state')
    const error = c.req.query('error')
    const errorDescription = c.req.query('error_description')

    if (debug) {
      console.log('[OAuth] Callback received:', { code: !!code, state: upstreamState, error })
    }

    if (!code || !upstreamState) {
      return c.json({ error: 'invalid_request', error_description: 'Missing code or state' } as OAuthError, 400)
    }

    // In dev mode, callback shouldn't be used (login handles it directly)
    if (!upstream) {
      return c.json({ error: 'server_error', error_description: 'No upstream provider configured' } as OAuthError, 500)
    }

    // Check if this is a simple login flow (login: prefix) or OAuth flow (pending: prefix)
    const loginAuth = await storage.consumeAuthorizationCode(`login:${upstreamState}`)

    if (loginAuth) {
      // Simple login flow - use one-time code exchange (not JWT in URL)
      if (error) {
        const redirectUrl = new URL(loginAuth.redirectUri)
        redirectUrl.searchParams.set('error', error)
        if (errorDescription) {
          redirectUrl.searchParams.set('error_description', errorDescription)
        }
        return c.redirect(redirectUrl.toString())
      }

      try {
        // Exchange code with upstream provider
        // Use defaultIssuer for callback URL (registered with upstream provider)
        const upstreamTokens = await exchangeUpstreamCode(upstream, code, `${defaultIssuer}/api/callback`)

        if (debug) {
          console.log('[OAuth] Simple login - upstream tokens received')
        }

        // Get or create user
        const user = await getOrCreateUser(storage, upstreamTokens.user, onUserAuthenticated)

        // Generate JWT access token with stored effective issuer (for multi-tenant support)
        const tokenIssuer = loginAuth.effectiveIssuer || defaultIssuer
        const accessToken = await generateAccessToken(user, 'first-party', 'openid profile email', tokenIssuer)

        // Generate refresh token for silent refresh
        const refreshToken = generateToken(64)
        const now = Date.now()
        await storage.saveRefreshToken({
          token: refreshToken,
          clientId: 'first-party',
          userId: user.id,
          scope: 'openid profile email',
          issuedAt: now,
          ...(refreshTokenTtl > 0 && { expiresAt: now + refreshTokenTtl * 1000 }),
        })

        // Generate a one-time code and store both tokens (60 second TTL)
        const oneTimeCode = generateAuthorizationCode()
        await storage.saveAuthorizationCode({
          code: `exchange:${oneTimeCode}`,
          clientId: 'first-party',
          userId: user.id,
          redirectUri: loginAuth.redirectUri,
          exchangeAccessToken: accessToken,
          exchangeRefreshToken: refreshToken,
          issuedAt: Date.now(),
          expiresAt: Date.now() + 60 * 1000, // 60 second TTL
        })

        // Redirect to origin's /callback with one-time code
        const originalUrl = new URL(loginAuth.redirectUri)
        const callbackUrl = new URL('/callback', originalUrl.origin)
        callbackUrl.searchParams.set('code', oneTimeCode)
        callbackUrl.searchParams.set('returnTo', originalUrl.pathname + originalUrl.search)

        if (debug) {
          console.log('[OAuth] Platform login redirect:', callbackUrl.toString())
        }

        return c.redirect(callbackUrl.toString())
      } catch (err) {
        if (debug) {
          console.error('[OAuth] Simple login callback error:', err)
        }
        const redirectUrl = new URL(loginAuth.redirectUri)
        redirectUrl.searchParams.set('error', 'server_error')
        redirectUrl.searchParams.set('error_description', err instanceof Error ? err.message : 'Authentication failed')
        return c.redirect(redirectUrl.toString())
      }
    }

    // OAuth flow - look for pending: prefix
    if (error) {
      // Retrieve pending auth to get redirect_uri
      const pendingAuth = await storage.consumeAuthorizationCode(`pending:${upstreamState}`)
      if (pendingAuth) {
        return redirectWithError(pendingAuth.redirectUri, error, errorDescription, pendingAuth.state)
      }
      return c.json({ error, error_description: errorDescription } as OAuthError, 400)
    }

    // Retrieve pending authorization
    const pendingAuth = await storage.consumeAuthorizationCode(`pending:${upstreamState}`)
    if (!pendingAuth) {
      return c.json({ error: 'invalid_request', error_description: 'Invalid or expired state' } as OAuthError, 400)
    }

    // CSRF Protection: Explicitly validate the upstream state matches what was stored
    // This is defense-in-depth - the lookup by state already provides implicit validation,
    // but explicit comparison ensures the state wasn't somehow tampered with
    if (pendingAuth.upstreamState && pendingAuth.upstreamState !== upstreamState) {
      if (debug) {
        console.log('[OAuth] State mismatch - potential CSRF attack detected')
      }
      return redirectWithError(
        pendingAuth.redirectUri,
        'access_denied',
        'State parameter validation failed - possible CSRF attack',
        pendingAuth.state
      )
    }

    try {
      // Exchange code with upstream provider
      // Use defaultIssuer for callback URL (registered with upstream provider)
      const upstreamTokens = await exchangeUpstreamCode(upstream, code, `${defaultIssuer}/api/callback`)

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
        ...(pendingAuth.scope !== undefined && { scope: pendingAuth.scope }),
        ...(pendingAuth.codeChallenge !== undefined && { codeChallenge: pendingAuth.codeChallenge }),
        codeChallengeMethod: 'S256',
        ...(pendingAuth.state !== undefined && { state: pendingAuth.state }),
        ...(pendingAuth.effectiveIssuer !== undefined && { effectiveIssuer: pendingAuth.effectiveIssuer }),
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

    const grantType = params['grant_type']

    if (debug) {
      console.log('[OAuth] Token request:', { grantType, clientId: params['client_id'] })
    }

    // JWT signing options
    // Note: issuer is set to defaultIssuer but can be overridden per-token by effectiveIssuer in auth code
    const jwtSigningOptions = useJwtAccessTokens ? {
      issuer: defaultIssuer,
      getSigningKey: ensureSigningKey,
    } : undefined

    if (grantType === 'authorization_code') {
      return handleAuthorizationCodeGrant(c, params, storage, accessTokenTtl, refreshTokenTtl, debug, jwtSigningOptions)
    } else if (grantType === 'refresh_token') {
      return handleRefreshTokenGrant(c, params, storage, accessTokenTtl, refreshTokenTtl, debug, jwtSigningOptions)
    } else {
      return c.json({ error: 'unsupported_grant_type', error_description: 'Only authorization_code and refresh_token grants are supported' } as OAuthError, 400)
    }
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Platform Token Exchange (for first-party domains)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Exchange a one-time code for a JWT (platform domains only)
   *
   * This is used by platform domains after the OAuth callback.
   * The one-time code is exchanged server-side for the JWT,
   * which is then set as an httpOnly cookie.
   *
   * POST /exchange { code: "one-time-code" }
   * Returns: { token: "jwt", expiresIn: 3600 }
   */
  app.post('/exchange', async (c) => {
    // Validate origin to prevent intercepted codes from being exchanged by unauthorized parties
    const origin = c.req.header('Origin') || c.req.header('Referer')
    if (origin) {
      try {
        const originUrl = new URL(origin)
        const issuerUrl = new URL(defaultIssuer)
        const isAllowed = corsOrigins.includes('*') ||
          corsOrigins.includes(originUrl.origin) ||
          originUrl.origin === issuerUrl.origin
        if (!isAllowed) {
          return c.json({ error: 'invalid_request', error_description: 'Origin not allowed' } as OAuthError, 403)
        }
      } catch {
        return c.json({ error: 'invalid_request', error_description: 'Invalid Origin header' } as OAuthError, 400)
      }
    } else if (!devMode?.enabled) {
      // In production, require Origin or Referer header
      return c.json({ error: 'invalid_request', error_description: 'Origin header is required' } as OAuthError, 403)
    }

    const body = await c.req.json<{ code: string }>()
    const code = body.code

    if (!code) {
      return c.json({ error: 'invalid_request', error_description: 'code is required' } as OAuthError, 400)
    }

    // Look up the one-time code
    const exchangeData = await storage.consumeAuthorizationCode(`exchange:${code}`)
    if (!exchangeData) {
      return c.json({ error: 'invalid_grant', error_description: 'Invalid or expired code' } as OAuthError, 400)
    }

    const accessToken = exchangeData.exchangeAccessToken
    const refreshToken = exchangeData.exchangeRefreshToken

    if (debug) {
      console.log('[OAuth] Platform exchange successful for user:', exchangeData.userId)
    }

    return c.json({
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: 'Bearer',
      expires_in: accessTokenTtl,
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Dynamic Client Registration
  // ═══════════════════════════════════════════════════════════════════════════

  if (enableDynamicRegistration) {
    /**
     * Client registration endpoint (RFC 7591)
     */
    app.post('/register', async (c) => {
      // Check if authentication is required
      if (requireRegistrationAuth || adminToken) {
        const xAdminToken = c.req.header('x-admin-token')
        const authHeader = c.req.header('authorization')
        let authenticated = false

        // Check admin token
        if (adminToken && xAdminToken === adminToken) {
          authenticated = true
        }

        // Check Bearer token (must be a valid access token)
        if (!authenticated && authHeader?.startsWith('Bearer ')) {
          const token = authHeader.slice(7)
          // Verify it's a valid token in storage
          const storedToken = await storage.getAccessToken(token)
          if (storedToken && Date.now() <= storedToken.expiresAt) {
            authenticated = true
          }
        }

        if (!authenticated) {
          return c.json({ error: 'unauthorized', error_description: 'Authentication required for client registration' } as OAuthError, 401)
        }
      }

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
        ...(body.scope !== undefined && { scope: body.scope }),
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
  // UserInfo Endpoint (OpenID Connect)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * OpenID Connect UserInfo endpoint
   * Returns claims about the authenticated user based on granted scopes.
   */
  app.get('/userinfo', async (c) => {
    const authHeader = c.req.header('authorization')
    if (!authHeader?.startsWith('Bearer ')) {
      c.header('WWW-Authenticate', 'Bearer')
      return c.json({ error: 'invalid_token', error_description: 'Bearer token required' }, 401)
    }

    const token = authHeader.slice(7)
    let userId: string | undefined
    let grantedScope: string | undefined

    // Try JWT first
    const decoded = decodeJWT(token)
    if (decoded) {
      // Verify JWT signature
      let signatureValid = false
      if (signingKeyManager || useJwtAccessTokens) {
        try {
          const key = await ensureSigningKey()
          const effectiveIssuer = getEffectiveIssuer(c)
          const result = await verifyJWT(token, {
            publicKey: key.publicKey,
            issuer: decoded.payload.iss === effectiveIssuer ? effectiveIssuer : defaultIssuer,
          })
          signatureValid = result.valid
        } catch {
          signatureValid = false
        }
      }

      if (!signatureValid) {
        c.header('WWW-Authenticate', 'Bearer error="invalid_token"')
        return c.json({ error: 'invalid_token', error_description: 'Token verification failed' }, 401)
      }

      const now = Math.floor(Date.now() / 1000)
      if (decoded.payload.exp && decoded.payload.exp < now) {
        c.header('WWW-Authenticate', 'Bearer error="invalid_token"')
        return c.json({ error: 'invalid_token', error_description: 'Token expired' }, 401)
      }

      userId = decoded.payload.sub
      grantedScope = decoded.payload['scope'] as string | undefined
    } else {
      // Opaque token - look up in storage
      const storedToken = await storage.getAccessToken(token)
      if (!storedToken || Date.now() > storedToken.expiresAt) {
        c.header('WWW-Authenticate', 'Bearer error="invalid_token"')
        return c.json({ error: 'invalid_token', error_description: 'Token is invalid or expired' }, 401)
      }
      userId = storedToken.userId
      grantedScope = storedToken.scope
    }

    if (!userId) {
      c.header('WWW-Authenticate', 'Bearer error="invalid_token"')
      return c.json({ error: 'invalid_token', error_description: 'Token has no subject' }, 401)
    }

    const user = await storage.getUser(userId)
    if (!user) {
      c.header('WWW-Authenticate', 'Bearer error="invalid_token"')
      return c.json({ error: 'invalid_token', error_description: 'User not found' }, 401)
    }

    // Build claims based on granted scopes
    const scopeSet = new Set((grantedScope || '').split(/\s+/).filter(Boolean))

    // 'sub' is always returned per OIDC spec
    const claims: Record<string, unknown> = { sub: user.id }

    // 'profile' scope: name, picture, etc.
    if (scopeSet.has('profile')) {
      if (user.name) claims.name = user.name
      if (user.metadata?.picture) claims.picture = user.metadata.picture
    }

    // 'email' scope: email, email_verified
    if (scopeSet.has('email')) {
      if (user.email) {
        claims.email = user.email
        claims.email_verified = true // Upstream provider already verified
      }
    }

    return c.json(claims)
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Token Revocation
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Token revocation endpoint (RFC 7009)
   */
  app.post('/revoke', async (c) => {
    const formData = await c.req.parseBody()
    const token = String(formData['token'] || '')
    const tokenTypeHint = String(formData['token_type_hint'] || '')

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

/**
 * Result of client authentication
 */
interface ClientAuthResult {
  success: boolean
  client?: OAuthClient
  error?: string
  errorDescription?: string
  statusCode?: number
}

/**
 * Authenticate a client at the token endpoint
 *
 * Supports:
 * - client_secret_basic: Authorization: Basic base64(client_id:client_secret)
 * - client_secret_post: client_id and client_secret in request body
 * - none: public clients (no secret required)
 */
async function authenticateClient(
  c: Context,
  params: Record<string, string>,
  storage: OAuthStorage,
  debug: boolean
): Promise<ClientAuthResult> {
  let clientId: string | undefined
  let clientSecret: string | undefined

  // Check for client_secret_basic (Authorization header)
  const authHeader = c.req.header('authorization')
  if (authHeader?.startsWith('Basic ')) {
    try {
      const base64Credentials = authHeader.slice(6)
      const credentials = atob(base64Credentials)
      const colonIndex = credentials.indexOf(':')
      if (colonIndex !== -1) {
        clientId = decodeURIComponent(credentials.slice(0, colonIndex))
        clientSecret = decodeURIComponent(credentials.slice(colonIndex + 1))
      }
    } catch {
      return {
        success: false,
        error: 'invalid_client',
        errorDescription: 'Invalid Authorization header',
        statusCode: 401,
      }
    }
  }

  // Fall back to client_secret_post (body parameters)
  if (!clientId) {
    clientId = params['client_id']
    clientSecret = params['client_secret']
  }

  if (!clientId) {
    return {
      success: false,
      error: 'invalid_request',
      errorDescription: 'client_id is required',
      statusCode: 400,
    }
  }

  // Fetch the client
  const client = await storage.getClient(clientId)
  if (!client) {
    return {
      success: false,
      error: 'invalid_client',
      errorDescription: 'Client not found',
      statusCode: 401,
    }
  }

  // Check if client requires authentication
  if (client.tokenEndpointAuthMethod !== 'none') {
    // Client requires secret verification
    if (!client.clientSecretHash) {
      // Client is configured to require auth but has no secret stored
      return {
        success: false,
        error: 'invalid_client',
        errorDescription: 'Client authentication failed',
        statusCode: 401,
      }
    }

    if (!clientSecret) {
      return {
        success: false,
        error: 'invalid_client',
        errorDescription: 'Client secret is required',
        statusCode: 401,
      }
    }

    // Verify the secret using constant-time comparison
    const secretValid = await verifyClientSecret(clientSecret, client.clientSecretHash)
    if (!secretValid) {
      if (debug) {
        console.log('[OAuth] Client authentication failed for:', clientId)
      }
      return {
        success: false,
        error: 'invalid_client',
        errorDescription: 'Client authentication failed',
        statusCode: 401,
      }
    }
  }

  if (debug) {
    console.log('[OAuth] Client authenticated:', clientId)
  }

  return {
    success: true,
    client,
  }
}

function redirectWithError(redirectUri: string, error: string, description?: string, state?: string): Response {
  try {
    const url = new URL(redirectUri)
    url.searchParams.set('error', error)
    if (description) {
      url.searchParams.set('error_description', description)
    }
    if (state) {
      url.searchParams.set('state', state)
    }
    return Response.redirect(url.toString(), 302)
  } catch {
    // If redirect_uri is malformed, return a JSON error response instead of redirecting
    return new Response(JSON.stringify({
      error,
      error_description: description || 'Invalid redirect_uri',
    }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    })
  }
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

/**
 * User info extracted from upstream provider
 */
interface UpstreamUser {
  id: string
  email: string
  first_name?: string
  last_name?: string
  organization_id?: string
  role?: string
  roles?: string[]
  permissions?: string[]
}

async function exchangeUpstreamCode(
  upstream: UpstreamOAuthConfig,
  code: string,
  redirectUri: string
): Promise<{
  access_token: string
  refresh_token?: string
  expires_in?: number
  user: UpstreamUser
}> {
  if (upstream.provider === 'workos') {
    const response = await fetch('https://api.workos.com/user_management/authenticate', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: upstream.clientId,
        client_secret: upstream.apiKey,
        code,
      }).toString(),
    })

    if (!response.ok) {
      const error = await response.text()
      throw new Error(`WorkOS authentication failed: ${response.status} - ${error}`)
    }

    const data = await response.json() as {
      access_token: string
      refresh_token?: string
      expires_in?: number
      user: UpstreamUser
    }

    // Extract roles from WorkOS JWT access_token
    // The WorkOS JWT contains 'role' claim for the user's role in the organization
    try {
      const decoded = decodeJWT(data.access_token)
      if (decoded?.payload) {
        // WorkOS uses 'role' for single role (from organization membership)
        const role = decoded.payload['role'] as string | undefined
        // Some setups may use 'roles' array
        const roles = decoded.payload['roles'] as string[] | undefined
        // Permissions may also be in the JWT
        const permissions = decoded.payload['permissions'] as string[] | undefined

        // Merge role info into user object
        if (role) {
          data.user.role = role
          // Also add to roles array for consistency
          data.user.roles = roles ? [...roles, role] : [role]
        } else if (roles) {
          data.user.roles = roles
        }

        if (permissions) {
          data.user.permissions = permissions
        }
      }
    } catch {
      // JWT decode failed - continue without roles
      // Roles may come from a different source (API calls, etc.)
    }

    return data
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
  upstreamUser: UpstreamUser,
  onUserAuthenticated?: (user: OAuthUser) => void | Promise<void>
): Promise<OAuthUser> {
  // Try to find existing user by email
  let user = await storage.getUserByEmail(upstreamUser.email)

  if (!user) {
    // Create new user
    const fullName = [upstreamUser.first_name, upstreamUser.last_name].filter(Boolean).join(' ')
    user = {
      id: upstreamUser.id,
      email: upstreamUser.email,
      ...(fullName && { name: fullName }),
      ...(upstreamUser.organization_id !== undefined && { organizationId: upstreamUser.organization_id }),
      ...(upstreamUser.roles && upstreamUser.roles.length > 0 && { roles: upstreamUser.roles }),
      ...(upstreamUser.permissions && upstreamUser.permissions.length > 0 && { permissions: upstreamUser.permissions }),
      createdAt: Date.now(),
      updatedAt: Date.now(),
      lastLoginAt: Date.now(),
    }
    await storage.saveUser(user)
  } else {
    // Update last login and refresh roles/permissions from upstream
    user.lastLoginAt = Date.now()
    user.updatedAt = Date.now()
    // Update org, roles, permissions on each login (they may change in upstream)
    if (upstreamUser.organization_id !== undefined) {
      user.organizationId = upstreamUser.organization_id
    }
    if (upstreamUser.roles && upstreamUser.roles.length > 0) {
      user.roles = upstreamUser.roles
    }
    if (upstreamUser.permissions && upstreamUser.permissions.length > 0) {
      user.permissions = upstreamUser.permissions
    }
    await storage.saveUser(user)
  }

  if (onUserAuthenticated) {
    await onUserAuthenticated(user)
  }

  return user
}

/**
 * JWT signing options passed from token endpoint
 */
interface JWTSigningOptions {
  issuer: string
  getSigningKey: () => Promise<{
    kid: string
    alg: 'RS256'
    privateKey: CryptoKey
    publicKey: CryptoKey
    createdAt: number
  }>
}

/**
 * Sign a JWT access token
 */
async function signJWTAccessToken(
  claims: AccessTokenClaims,
  options: JWTSigningOptions,
  expiresIn: number
): Promise<string> {
  const { signAccessToken } = await import('./jwt-signing.js')
  const key = await options.getSigningKey()
  return signAccessToken(key, claims, {
    issuer: options.issuer,
    audience: claims.client_id,
    expiresIn,
  })
}

async function handleAuthorizationCodeGrant(
  c: Context,
  params: Record<string, string>,
  storage: OAuthStorage,
  accessTokenTtl: number,
  refreshTokenTtl: number,
  debug: boolean,
  jwtOptions?: JWTSigningOptions
): Promise<Response> {
  const code = params['code']
  const redirect_uri = params['redirect_uri']
  const code_verifier = params['code_verifier']

  if (!code) {
    return c.json({ error: 'invalid_request', error_description: 'code is required' } as OAuthError, 400)
  }

  // Authenticate client (supports client_secret_basic and client_secret_post)
  const authResult = await authenticateClient(c, params, storage, debug)
  if (!authResult.success) {
    const statusCode = (authResult.statusCode || 401) as 400 | 401
    return c.json(
      { error: authResult.error, error_description: authResult.errorDescription } as OAuthError,
      statusCode
    )
  }
  const client = authResult.client!

  // Consume authorization code (one-time use)
  const authCode = await storage.consumeAuthorizationCode(code)
  if (!authCode) {
    return c.json({ error: 'invalid_grant', error_description: 'Invalid or expired authorization code' } as OAuthError, 400)
  }

  // Verify client matches the code
  if (authCode.clientId !== client.clientId) {
    return c.json({ error: 'invalid_grant', error_description: 'Client mismatch' } as OAuthError, 400)
  }

  // Verify redirect_uri
  if (redirect_uri && authCode.redirectUri !== redirect_uri) {
    return c.json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' } as OAuthError, 400)
  }

  // Verify PKCE (required in OAuth 2.1)
  // Per OAuth 2.1 spec, PKCE is REQUIRED for authorization_code flow
  if (!authCode.codeChallenge) {
    // This should never happen if the authorize endpoint is working correctly
    return c.json({ error: 'server_error', error_description: 'Authorization code missing code_challenge' } as OAuthError, 500)
  }

  if (!code_verifier) {
    return c.json({ error: 'invalid_request', error_description: 'code_verifier is required' } as OAuthError, 400)
  }

  const valid = await verifyCodeChallenge(code_verifier, authCode.codeChallenge, authCode.codeChallengeMethod || 'S256')
  if (!valid) {
    return c.json({ error: 'invalid_grant', error_description: 'Invalid code_verifier' } as OAuthError, 400)
  }

  // Check expiration
  if (Date.now() > authCode.expiresAt) {
    return c.json({ error: 'invalid_grant', error_description: 'Authorization code expired' } as OAuthError, 400)
  }

  // Generate tokens
  const refreshToken = generateToken(64)
  const now = Date.now()

  // Generate access token (JWT if configured, otherwise opaque)
  let accessToken: string
  if (jwtOptions) {
    // Use effectiveIssuer from auth code if set (for multi-tenant support)
    const tokenJwtOptions = authCode.effectiveIssuer
      ? { ...jwtOptions, issuer: authCode.effectiveIssuer }
      : jwtOptions
    accessToken = await signJWTAccessToken(
      {
        sub: authCode.userId,
        client_id: authCode.clientId,
        ...(authCode.scope && { scope: authCode.scope }),
      },
      tokenJwtOptions,
      accessTokenTtl
    )
    // Note: JWT access tokens are stateless, so we don't store them
    // But we can optionally store metadata for tracking/revocation
  } else {
    accessToken = generateToken(48)
    await storage.saveAccessToken({
      token: accessToken,
      tokenType: 'Bearer',
      clientId: authCode.clientId,
      userId: authCode.userId,
      ...(authCode.scope !== undefined && { scope: authCode.scope }),
      issuedAt: now,
      expiresAt: now + accessTokenTtl * 1000,
    })
  }

  await storage.saveRefreshToken({
    token: refreshToken,
    clientId: authCode.clientId,
    userId: authCode.userId,
    ...(authCode.scope !== undefined && { scope: authCode.scope }),
    issuedAt: now,
    ...(refreshTokenTtl > 0 && { expiresAt: now + refreshTokenTtl * 1000 }),
  })

  // Save grant
  await storage.saveGrant({
    id: `${authCode.userId}:${authCode.clientId}`,
    userId: authCode.userId,
    clientId: authCode.clientId,
    ...(authCode.scope !== undefined && { scope: authCode.scope }),
    createdAt: now,
    lastUsedAt: now,
  })

  if (debug) {
    console.log('[OAuth] Tokens issued for user:', authCode.userId, jwtOptions ? '(JWT)' : '(opaque)')
  }

  const response: TokenResponse = {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: accessTokenTtl,
    refresh_token: refreshToken,
    ...(authCode.scope !== undefined && { scope: authCode.scope }),
  }

  return c.json(response)
}

async function handleRefreshTokenGrant(
  c: Context,
  params: Record<string, string>,
  storage: OAuthStorage,
  accessTokenTtl: number,
  refreshTokenTtl: number,
  debug: boolean,
  jwtOptions?: JWTSigningOptions
): Promise<Response> {
  const refresh_token = params['refresh_token']

  if (!refresh_token) {
    return c.json({ error: 'invalid_request', error_description: 'refresh_token is required' } as OAuthError, 400)
  }

  // Authenticate client (supports client_secret_basic and client_secret_post)
  const authResult = await authenticateClient(c, params, storage, debug)
  if (!authResult.success) {
    const statusCode = (authResult.statusCode || 401) as 400 | 401
    return c.json(
      { error: authResult.error, error_description: authResult.errorDescription } as OAuthError,
      statusCode
    )
  }
  const client = authResult.client!

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

  // Verify the refresh token belongs to the authenticated client
  if (storedRefresh.clientId !== client.clientId) {
    return c.json({ error: 'invalid_grant', error_description: 'Client mismatch' } as OAuthError, 400)
  }

  // Generate new tokens
  const newRefreshToken = generateToken(64)
  const now = Date.now()

  // Generate access token (JWT if configured, otherwise opaque)
  let accessToken: string
  if (jwtOptions) {
    accessToken = await signJWTAccessToken(
      {
        sub: storedRefresh.userId,
        client_id: storedRefresh.clientId,
        ...(storedRefresh.scope && { scope: storedRefresh.scope }),
      },
      jwtOptions,
      accessTokenTtl
    )
  } else {
    accessToken = generateToken(48)
    await storage.saveAccessToken({
      token: accessToken,
      tokenType: 'Bearer',
      clientId: storedRefresh.clientId,
      userId: storedRefresh.userId,
      ...(storedRefresh.scope !== undefined && { scope: storedRefresh.scope }),
      issuedAt: now,
      expiresAt: now + accessTokenTtl * 1000,
    })
  }

  // Rotate refresh token
  await storage.revokeRefreshToken(refresh_token)
  await storage.saveRefreshToken({
    token: newRefreshToken,
    clientId: storedRefresh.clientId,
    userId: storedRefresh.userId,
    ...(storedRefresh.scope !== undefined && { scope: storedRefresh.scope }),
    issuedAt: now,
    ...(refreshTokenTtl > 0 && { expiresAt: now + refreshTokenTtl * 1000 }),
  })

  // Update grant last used
  const grant = await storage.getGrant(storedRefresh.userId, storedRefresh.clientId)
  if (grant) {
    grant.lastUsedAt = now
    await storage.saveGrant(grant)
  }

  if (debug) {
    console.log('[OAuth] Tokens refreshed for user:', storedRefresh.userId, jwtOptions ? '(JWT)' : '(opaque)')
  }

  const response: TokenResponse = {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: accessTokenTtl,
    refresh_token: newRefreshToken,
    ...(storedRefresh.scope !== undefined && { scope: storedRefresh.scope }),
  }

  return c.json(response)
}

// ═══════════════════════════════════════════════════════════════════════════
// JWT Verification Re-exports
// ═══════════════════════════════════════════════════════════════════════════

// Re-export JWT verification utilities for downstream consumers
export { verifyJWT, decodeJWT, isJWTExpired, clearJWKSCache } from './jwt.js'
export type { JWTVerifyResult, JWTVerifyOptions, JWTPayload, JWTHeader } from './jwt.js'
export { verifyJWTWithKeyManager } from './jwt-signing.js'
