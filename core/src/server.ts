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
 * - /device_authorization (RFC 8628 Device Authorization)
 * - /device (Device verification page)
 *
 * This server acts as a federated OAuth 2.1 server:
 * - It is an OAuth SERVER to downstream clients (Claude, ChatGPT, etc.)
 * - It is an OAuth CLIENT to upstream providers (WorkOS, Auth0, etc.)
 */

import { Hono } from 'hono'
import type { Context } from 'hono'
import { cors } from 'hono/cors'
import type { OAuthStorage } from './storage.js'
import type { OAuthResourceMetadata, OAuthUser, OAuthError, UpstreamOAuthConfig } from './types.js'
import type { DevModeConfig, DevUser, TestHelpers } from './dev.js'
import { createTestHelpers } from './dev.js'
import type { SigningKeyManager } from './jwt-signing.js'

// Import endpoint handlers
import {
  createAuthorizeHandler,
  createLoginGetHandler,
  createLoginPostHandler,
  createCallbackHandler,
  createExchangeHandler,
  handleAuthorizationCodeGrant,
  handleRefreshTokenGrant,
  handleClientCredentialsGrant,
  handleDeviceCodeGrant,
  createDeviceAuthorizationHandler,
  createDeviceGetHandler,
  createDevicePostHandler,
  createUserInfoHandler,
  createRegisterHandler,
  createIntrospectHandler,
  createRevokeHandler,
  type JWTSigningOptions,
} from './endpoints/index.js'

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
  /**
   * Callback after token revocation (RFC 7009)
   * Use this to invalidate caches (e.g., auth worker cache) when tokens are revoked.
   * The callback receives the revoked token value.
   */
  onTokenRevoked?: (token: string, tokenTypeHint?: string) => void | Promise<void>
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
    onTokenRevoked,
    debug = false,
    allowedOrigins,
    signingKeyManager: providedSigningKeyManager,
    useJwtAccessTokens = false,
    trustedIssuers,
    requireRegistrationAuth = false,
    adminToken,
  } = config

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

  /**
   * Get the effective issuer for a request.
   * Supports dynamic issuers via X-Issuer header for multi-tenant scenarios.
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

  /** Check if a redirect URI requires HTTPS (production enforcement) */
  function validateRedirectUriScheme(uri: string): string | null {
    if (devMode?.enabled) return null
    try {
      const parsed = new URL(uri)
      const host = parsed.hostname
      if (parsed.protocol === 'http:' && host !== 'localhost' && host !== '127.0.0.1') {
        return 'redirect_uri must use HTTPS (except for localhost development)'
      }
    } catch {
      // URL parsing errors are handled elsewhere
    }
    return null
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

  // Helper to generate JWT access token for simple login flow
  // Accepts optional issuer override for multi-tenant scenarios
  async function generateAccessToken(user: OAuthUser, clientId: string, scope: string, issuerOverride?: string): Promise<string> {
    const { signAccessToken } = await import('./jwt-signing.js')
    const key = await ensureSigningKey()
    return signAccessToken(
      key,
      {
        sub: user.id,
        client_id: clientId,
        scope,
        email: user.email,
        name: user.name,
        // Include RBAC claims from user
        ...(user.organizationId && { org_id: user.organizationId }),
        ...(user.roles && user.roles.length > 0 && { roles: user.roles }),
        ...(user.permissions && user.permissions.length > 0 && { permissions: user.permissions }),
      },
      {
        issuer: issuerOverride || defaultIssuer,
        audience: clientId,
        expiresIn: accessTokenTtl,
      }
    )
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
  app.use(
    '*',
    cors({
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
    })
  )

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
      device_authorization_endpoint: `${issuer}/device_authorization`,
      grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials', 'urn:ietf:params:oauth:grant-type:device_code'],
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

  // ═══════════════════════════════════════════════════════════════════════════
  // Token Introspection Endpoint (RFC 7662)
  // ═══════════════════════════════════════════════════════════════════════════

  app.post(
    '/introspect',
    createIntrospectHandler({
      defaultIssuer,
      storage,
      signingKeyManager,
      useJwtAccessTokens,
      debug,
      getEffectiveIssuer,
      ensureSigningKey,
      getSigningKeyManager: () => signingKeyManager,
    })
  )

  // ═══════════════════════════════════════════════════════════════════════════
  // Authorization Endpoint
  // ═══════════════════════════════════════════════════════════════════════════

  // Shared config for authorization handlers
  const authorizeHandlerConfig = {
    defaultIssuer,
    storage,
    upstream,
    devMode,
    scopes,
    accessTokenTtl,
    refreshTokenTtl,
    authCodeTtl,
    onUserAuthenticated,
    debug,
    corsOrigins,
    testHelpers: app.testHelpers,
    getEffectiveIssuer,
    validateRedirectUriScheme,
    validateScopes,
    generateAccessToken,
  }

  app.get('/authorize', createAuthorizeHandler(authorizeHandlerConfig))

  // ═══════════════════════════════════════════════════════════════════════════
  // Simple Login Endpoint (for first-party apps)
  // ═══════════════════════════════════════════════════════════════════════════

  app.get('/login', createLoginGetHandler(authorizeHandlerConfig))

  // ═══════════════════════════════════════════════════════════════════════════
  // Dev Mode Login Endpoint
  // ═══════════════════════════════════════════════════════════════════════════

  app.post('/login', createLoginPostHandler(authorizeHandlerConfig))

  // ═══════════════════════════════════════════════════════════════════════════
  // Upstream OAuth Callback
  // ═══════════════════════════════════════════════════════════════════════════

  app.get('/api/callback', createCallbackHandler(authorizeHandlerConfig))

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
      try {
        const raw: unknown = await c.req.json()
        if (typeof raw !== 'object' || raw === null) {
          return c.json({ error: 'invalid_request', error_description: 'Request body must be a JSON object' } as OAuthError, 400)
        }
        // Coerce all values to strings for consistent handling
        params = Object.fromEntries(Object.entries(raw as Record<string, unknown>).map(([k, v]) => [k, v == null ? '' : String(v)]))
      } catch {
        return c.json({ error: 'invalid_request', error_description: 'Invalid JSON body' } as OAuthError, 400)
      }
    } else {
      const formData = await c.req.parseBody()
      params = Object.fromEntries(Object.entries(formData).map(([k, v]) => [k, String(v)]))
    }

    const grantType = params['grant_type']

    if (debug) {
      console.log('[OAuth] Token request:', { grantType, clientId: params['client_id'] })
    }

    // JWT signing options
    // Note: issuer is set to defaultIssuer but can be overridden per-token by effectiveIssuer in auth code
    const jwtSigningOptions: JWTSigningOptions | undefined = useJwtAccessTokens
      ? {
          issuer: defaultIssuer,
          getSigningKey: ensureSigningKey,
        }
      : undefined

    if (grantType === 'authorization_code') {
      return handleAuthorizationCodeGrant(c, params, storage, accessTokenTtl, refreshTokenTtl, debug, jwtSigningOptions)
    } else if (grantType === 'refresh_token') {
      return handleRefreshTokenGrant(c, params, storage, accessTokenTtl, refreshTokenTtl, debug, jwtSigningOptions)
    } else if (grantType === 'client_credentials') {
      return handleClientCredentialsGrant(c, params, storage, accessTokenTtl, debug, jwtSigningOptions)
    } else if (grantType === 'urn:ietf:params:oauth:grant-type:device_code') {
      return handleDeviceCodeGrant(c, params, storage, accessTokenTtl, refreshTokenTtl, debug, jwtSigningOptions)
    } else if (grantType === 'device_code') {
      // Also accept short form for convenience
      return handleDeviceCodeGrant(c, params, storage, accessTokenTtl, refreshTokenTtl, debug, jwtSigningOptions)
    } else {
      return c.json({ error: 'unsupported_grant_type', error_description: 'grant_type not supported' } as OAuthError, 400)
    }
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Platform Token Exchange (for first-party domains)
  // ═══════════════════════════════════════════════════════════════════════════

  app.post('/exchange', createExchangeHandler(authorizeHandlerConfig))

  // ═══════════════════════════════════════════════════════════════════════════
  // Dynamic Client Registration
  // ═══════════════════════════════════════════════════════════════════════════

  if (enableDynamicRegistration) {
    app.post(
      '/register',
      createRegisterHandler({
        storage,
        debug,
        requireRegistrationAuth,
        adminToken,
        validateRedirectUriScheme,
      })
    )
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // UserInfo Endpoint (OpenID Connect)
  // ═══════════════════════════════════════════════════════════════════════════

  app.get(
    '/userinfo',
    createUserInfoHandler({
      defaultIssuer,
      storage,
      signingKeyManager,
      useJwtAccessTokens,
      debug,
      getEffectiveIssuer,
      ensureSigningKey,
    })
  )

  // ═══════════════════════════════════════════════════════════════════════════
  // Token Revocation
  // ═══════════════════════════════════════════════════════════════════════════

  app.post(
    '/revoke',
    createRevokeHandler({
      storage,
      onTokenRevoked,
    })
  )

  // ═══════════════════════════════════════════════════════════════════════════
  // Device Authorization Grant (RFC 8628)
  // ═══════════════════════════════════════════════════════════════════════════

  const deviceHandlerConfig = {
    storage,
    debug,
    devMode,
    getEffectiveIssuer,
    validateScopes,
  }

  app.post('/device_authorization', createDeviceAuthorizationHandler(deviceHandlerConfig))
  app.get('/device', createDeviceGetHandler(deviceHandlerConfig))
  app.post('/device', createDevicePostHandler(deviceHandlerConfig))

  return app
}

// ═══════════════════════════════════════════════════════════════════════════
// JWT Verification Re-exports
// ═══════════════════════════════════════════════════════════════════════════

// Re-export JWT verification utilities for downstream consumers
export { verifyJWT, decodeJWT, isJWTExpired, clearJWKSCache } from './jwt.js'
export type { JWTVerifyResult, JWTVerifyOptions, JWTPayload, JWTHeader } from './jwt.js'
export { verifyJWTWithKeyManager } from './jwt-signing.js'
