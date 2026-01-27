/**
 * @dotdo/oauth - OAuth 2.1 Server for MCP
 *
 * A minimal OAuth 2.1 authorization server implementation designed for
 * Model Context Protocol (MCP) compatibility with Claude, ChatGPT, and other AI clients.
 *
 * This package is the "leaf" in the dependency tree - it has no dependencies on
 * oauth.do or @dotdo/do, allowing them to depend on it without circular dependencies.
 *
 * @example Basic usage
 * ```typescript
 * import { createOAuth21Server, MemoryOAuthStorage } from '@dotdo/oauth'
 *
 * const server = createOAuth21Server({
 *   issuer: 'https://mcp.do',
 *   storage: new MemoryOAuthStorage(),
 *   upstream: {
 *     provider: 'workos',
 *     apiKey: env.WORKOS_API_KEY,
 *     clientId: env.WORKOS_CLIENT_ID,
 *   },
 * })
 *
 * // Mount on Hono app
 * app.route('/', server)
 * ```
 *
 * @example With DO storage (provided by @dotdo/do)
 * ```typescript
 * import { createOAuth21Server } from '@dotdo/oauth'
 * import { DOAuthStorage } from '@dotdo/do/oauth'
 *
 * const server = createOAuth21Server({
 *   issuer: 'https://mcp.do',
 *   storage: new DOAuthStorage(digitalObject),
 *   upstream: { ... },
 * })
 * ```
 *
 * @packageDocumentation
 */

// Server
export { createOAuth21Server } from './server.js'
export type { OAuth21ServerConfig, OAuth21Server } from './server.js'

// Dev Mode & Test Helpers
export { createTestHelpers, generateLoginFormHtml } from './dev.js'
export type { DevModeConfig, DevUser, TestHelpers } from './dev.js'

// Storage
export { MemoryOAuthStorage } from './storage.js'
export type { OAuthStorage, ListOptions } from './storage.js'

// DO SQLite Storage (legacy - use CollectionsOAuthStorage instead)
export { DOSQLiteStorage } from './storage-do.js'
export type { SqlStorage, SqlStorageResult, OAuthUserWithStripe, SerializedSigningKeyRow } from './storage-do.js'

// Collections-based Storage (preferred - no migrations needed)
export { CollectionsOAuthStorage } from './storage-collections.js'

// PKCE
export {
  generateCodeVerifier,
  generateCodeChallenge,
  verifyCodeChallenge,
  generatePkce,
  generateState,
  generateToken,
  generateAuthorizationCode,
  hashClientSecret,
  verifyClientSecret,
  base64UrlEncode,
  base64UrlDecode,
  constantTimeEqual,
} from './pkce.js'

// JWT Verification
export { verifyJWT, decodeJWT, isJWTExpired, clearJWKSCache } from './jwt.js'
export type { JWTVerifyResult, JWTVerifyOptions, JWTHeader, JWTPayload } from './jwt.js'

// JWT Signing
export {
  SigningKeyManager,
  generateSigningKey,
  serializeSigningKey,
  deserializeSigningKey,
  exportPublicKeyToJWKS,
  exportKeysToJWKS,
  signAccessToken,
} from './jwt-signing.js'
export type {
  SigningKey,
  SerializedSigningKey,
  JWKSPublicKey,
  JWKS,
  AccessTokenClaims,
} from './jwt-signing.js'

// Stripe Integration
export {
  ensureStripeCustomer,
  getStripeCustomer,
  linkStripeCustomer,
  handleStripeWebhook,
  verifyStripeWebhook,
  verifyStripeWebhookAsync,
  createStripeClient,
} from './stripe.js'
export type {
  StripeCustomer,
  StripeSubscription,
  StripeWebhookEventType,
  StripeWebhookEvent,
  StripeStorage,
  StripeClient,
  OAuthUserWithStripe as StripeUser,
} from './stripe.js'

// Types
export type {
  OAuthUser,
  OAuthOrganization,
  OAuthClient,
  OAuthAuthorizationCode,
  OAuthAccessToken,
  OAuthRefreshToken,
  OAuthGrant,
  OAuthServerMetadata,
  OAuthResourceMetadata,
  TokenResponse,
  OAuthError,
  UpstreamOAuthConfig,
} from './types.js'
