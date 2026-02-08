/**
 * Authorization endpoint handlers (OAuth 2.1)
 *
 * Implements:
 * - GET /authorize - Authorization endpoint
 * - GET /login - Simple login redirect for first-party apps
 * - POST /login - Dev mode login form submission
 * - GET /api/callback - Upstream OAuth callback
 * - POST /exchange - Platform token exchange
 */

import type { Context } from 'hono'
import type { OAuthStorage } from '../storage.js'
import type { OAuthError, OAuthUser, UpstreamOAuthConfig } from '../types.js'
import type { DevModeConfig, TestHelpers } from '../dev.js'
import { generateLoginFormHtml } from '../dev.js'
import { generateAuthorizationCode, generateState, generateToken } from '../pkce.js'
import { redirectWithError } from '../utils/html.js'
import { buildUpstreamAuthUrl, exchangeUpstreamCode, getOrCreateUser } from '../utils/upstream.js'

/**
 * Configuration for authorization handlers
 */
export interface AuthorizeHandlerConfig {
  /** Default issuer URL */
  defaultIssuer: string
  /** Storage backend */
  storage: OAuthStorage
  /** Upstream OAuth provider configuration */
  upstream?: UpstreamOAuthConfig | undefined
  /** Development mode configuration */
  devMode?: DevModeConfig | undefined
  /** Supported scopes */
  scopes: string[]
  /** Access token TTL in seconds */
  accessTokenTtl: number
  /** Refresh token TTL in seconds */
  refreshTokenTtl: number
  /** Auth code TTL in seconds */
  authCodeTtl: number
  /** Callback after user authentication */
  onUserAuthenticated?: ((user: OAuthUser) => void | Promise<void>) | undefined
  /** Enable debug logging */
  debug: boolean
  /** Allowed CORS origins */
  corsOrigins: string[]
  /** Test helpers (only in dev mode) */
  testHelpers?: TestHelpers | undefined
  /** Function to get effective issuer from request */
  getEffectiveIssuer: (c: Context) => string
  /** Function to validate redirect URI scheme */
  validateRedirectUriScheme: (uri: string) => string | null
  /** Function to validate scopes */
  validateScopes: (requestedScope: string | undefined) => string | undefined
  /** Function to generate JWT access token */
  generateAccessToken: (user: OAuthUser, clientId: string, scope: string, issuerOverride?: string) => Promise<string>
}

/**
 * Create the authorization endpoint handler (GET /authorize)
 */
export function createAuthorizeHandler(config: AuthorizeHandlerConfig) {
  const {
    storage,
    upstream,
    devMode,
    defaultIssuer,
    authCodeTtl,
    debug,
    getEffectiveIssuer,
    validateRedirectUriScheme,
    validateScopes,
  } = config

  return async (c: Context): Promise<Response> => {
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

    // Enforce HTTPS for redirect URIs in production
    const schemeError = validateRedirectUriScheme(redirectUri)
    if (schemeError) {
      return c.json({ error: 'invalid_request', error_description: schemeError } as OAuthError, 400)
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
      const html =
        devMode.customLoginPage ||
        generateLoginFormHtml({
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
  }
}

/**
 * Create the login GET handler (GET /login) - Simple login redirect for first-party apps
 */
export function createLoginGetHandler(config: AuthorizeHandlerConfig) {
  const { storage, upstream, devMode, defaultIssuer, authCodeTtl, debug, corsOrigins, getEffectiveIssuer, generateAccessToken } = config

  return async (c: Context): Promise<Response> => {
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
  }
}

/**
 * Create the login POST handler (POST /login) - Dev mode login form submission
 */
export function createLoginPostHandler(config: AuthorizeHandlerConfig) {
  const { storage, devMode, authCodeTtl, debug, onUserAuthenticated, testHelpers, getEffectiveIssuer, validateScopes } = config

  return async (c: Context): Promise<Response> => {
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
    if (!testHelpers) {
      return c.json({ error: 'server_error', error_description: 'Test helpers not available' } as OAuthError, 500)
    }
    const devUser = await testHelpers.validateCredentials(email, password)
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
  }
}

/**
 * Create the callback handler (GET /api/callback) - Upstream OAuth callback
 */
export function createCallbackHandler(config: AuthorizeHandlerConfig) {
  const { storage, upstream, defaultIssuer, authCodeTtl, refreshTokenTtl, debug, onUserAuthenticated, generateAccessToken } = config

  return async (c: Context): Promise<Response> => {
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
      return redirectWithError(pendingAuth.redirectUri, 'access_denied', 'State parameter validation failed - possible CSRF attack', pendingAuth.state)
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
      return redirectWithError(pendingAuth.redirectUri, 'server_error', err instanceof Error ? err.message : 'Authentication failed', pendingAuth.state)
    }
  }
}

/**
 * Create the exchange handler (POST /exchange) - Platform token exchange
 */
export function createExchangeHandler(config: AuthorizeHandlerConfig) {
  const { storage, devMode, defaultIssuer, accessTokenTtl, debug, corsOrigins } = config

  return async (c: Context): Promise<Response> => {
    // Validate origin to prevent intercepted codes from being exchanged by unauthorized parties
    const origin = c.req.header('Origin') || c.req.header('Referer')
    if (origin) {
      try {
        const originUrl = new URL(origin)
        const issuerUrl = new URL(defaultIssuer)
        const isAllowed = corsOrigins.includes('*') || corsOrigins.includes(originUrl.origin) || originUrl.origin === issuerUrl.origin
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

    let body: unknown
    try {
      body = await c.req.json()
    } catch {
      return c.json({ error: 'invalid_request', error_description: 'Invalid JSON body' } as OAuthError, 400)
    }

    const code = (typeof body === 'object' && body !== null && typeof (body as Record<string, unknown>).code === 'string')
      ? (body as { code: string }).code
      : undefined

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
  }
}
