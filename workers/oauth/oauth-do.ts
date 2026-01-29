/**
 * OAuth Durable Object - Persistent OAuth 2.1 Server
 *
 * A Durable Object that implements the OAuth 2.1 server with SQLite storage.
 * This provides persistent storage for users, clients, tokens, and signing keys.
 */

import { DurableObject } from 'cloudflare:workers'
import { createOAuth21Server, CollectionsOAuthStorage, SigningKeyManager, type SerializedSigningKey } from '@dotdo/oauth'
import type { Hono } from 'hono'

/**
 * Environment bindings for the OAuth DO
 */
export interface OAuthDOEnv {
  WORKOS_API_KEY: string
  WORKOS_CLIENT_ID: string
  SIGNING_KEY_JWK?: string // RSA private key as JWK JSON string (use wrangler secret)
  STRIPE_SECRET_KEY?: string
  STRIPE_WEBHOOK_SECRET?: string
  ALLOWED_ORIGINS?: string
}

/**
 * OAuth Durable Object
 *
 * Provides a persistent OAuth 2.1 server with:
 * - SQLite storage for users, clients, tokens
 * - JWT signing with key rotation support
 * - WorkOS upstream authentication
 * - Optional Stripe integration
 */
export class OAuthDO extends DurableObject<OAuthDOEnv> {
  private app: Hono | null = null
  private storage: CollectionsOAuthStorage | null = null
  private keyManager: SigningKeyManager | null = null
  private initialized = false

  /**
   * Initialize the OAuth server lazily on first request
   */
  private async initialize(): Promise<void> {
    if (this.initialized) return

    // Create collections-based storage (no migrations needed)
    this.storage = new CollectionsOAuthStorage(this.ctx.storage.sql)

    // Create signing key manager
    this.keyManager = new SigningKeyManager({ maxKeys: 2 })

    // Load signing key from environment secret (preferred) or generate ephemeral
    if (this.env.SIGNING_KEY_JWK) {
      // Load from env secret - the secure way
      const keyData = JSON.parse(this.env.SIGNING_KEY_JWK) as SerializedSigningKey
      await this.keyManager.loadKeys([keyData])
    } else {
      // No env secret - generate ephemeral key (will change on DO restart)
      // This is fine for dev but not production
      console.warn('No SIGNING_KEY_JWK secret configured - using ephemeral key')
      await this.keyManager.getCurrentKey()
    }

    // Determine issuer from environment or default
    const issuer = 'https://oauth.do'

    // Parse allowed origins
    const allowedOrigins = this.env.ALLOWED_ORIGINS?.split(',').map((o) => o.trim()) ?? ['*']

    // Create OAuth 2.1 server
    this.app = createOAuth21Server({
      issuer,
      storage: this.storage,
      upstream: {
        provider: 'workos',
        apiKey: this.env.WORKOS_API_KEY,
        clientId: this.env.WORKOS_CLIENT_ID,
      },
      signingKeyManager: this.keyManager,
      useJwtAccessTokens: true,
      allowedOrigins,
      debug: false,
    })

    this.initialized = true
  }

  /**
   * Handle incoming HTTP requests
   */
  async fetch(request: Request): Promise<Response> {
    await this.initialize()

    if (!this.app) {
      return new Response('OAuth server not initialized', { status: 500 })
    }

    return this.app.fetch(request)
  }

  /**
   * Export current signing key for setting up SIGNING_KEY_JWK secret
   * Call this once to get the key, then store it via `wrangler secret put SIGNING_KEY_JWK`
   */
  async exportSigningKey(): Promise<SerializedSigningKey[]> {
    await this.initialize()

    if (!this.keyManager) {
      throw new Error('Not initialized')
    }

    return this.keyManager.exportKeys()
  }

  /**
   * Get storage adapter for direct access (e.g., from admin routes)
   */
  getStorage(): CollectionsOAuthStorage | null {
    return this.storage
  }

  /**
   * Get signing key manager for direct access
   */
  getKeyManager(): SigningKeyManager | null {
    return this.keyManager
  }
}
