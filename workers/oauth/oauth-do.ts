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

/** Interval for cleanup alarms (1 hour in milliseconds) */
const CLEANUP_ALARM_INTERVAL_MS = 60 * 60 * 1000

/**
 * OAuth Durable Object
 *
 * Provides a persistent OAuth 2.1 server with:
 * - SQLite storage for users, clients, tokens
 * - JWT signing with key rotation support
 * - WorkOS upstream authentication
 * - Optional Stripe integration
 * - Automatic cleanup of expired tokens via Durable Object alarms
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

    // Ensure signing keys table exists
    this.ctx.storage.sql.exec(
      'CREATE TABLE IF NOT EXISTS _signing_keys (kid TEXT PRIMARY KEY, key_data TEXT NOT NULL, created_at INTEGER NOT NULL)'
    )

    // Load signing key with priority: env secret > DO storage > generate + persist
    if (this.env.SIGNING_KEY_JWK) {
      // Load from env secret - the most secure option
      const keyData = JSON.parse(this.env.SIGNING_KEY_JWK) as SerializedSigningKey
      await this.keyManager.loadKeys([keyData])
    } else {
      // Try to load from DO SQLite storage (survives restarts)
      const storedKeys = this.ctx.storage.sql
        .exec('SELECT key_data FROM _signing_keys ORDER BY created_at DESC LIMIT 2')
        .toArray() as { key_data: string }[]

      if (storedKeys.length > 0) {
        const serializedKeys = storedKeys.map(row => JSON.parse(row.key_data) as SerializedSigningKey)
        await this.keyManager.loadKeys(serializedKeys)
      } else {
        // Generate a new key and persist it in DO storage
        console.warn('No SIGNING_KEY_JWK secret configured - generating and persisting key in DO storage')
        await this.keyManager.getCurrentKey()
        const exported = await this.keyManager.exportKeys()
        for (const serializedKey of exported) {
          this.ctx.storage.sql.exec(
            'INSERT OR REPLACE INTO _signing_keys (kid, key_data, created_at) VALUES (?, ?, ?)',
            serializedKey.kid,
            JSON.stringify(serializedKey),
            serializedKey.createdAt
          )
        }
      }
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

    // Schedule initial cleanup alarm if not already set
    await this.ensureAlarmScheduled()

    this.initialized = true
  }

  /**
   * Ensure a cleanup alarm is scheduled
   */
  private async ensureAlarmScheduled(): Promise<void> {
    const currentAlarm = await this.ctx.storage.getAlarm()
    if (currentAlarm === null) {
      // Schedule first alarm
      await this.ctx.storage.setAlarm(Date.now() + CLEANUP_ALARM_INTERVAL_MS)
    }
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
   * Handle Durable Object alarm for periodic cleanup
   *
   * This runs every hour to:
   * - Delete expired authorization codes (typically expire in 10 minutes)
   * - Delete expired access tokens
   */
  async alarm(): Promise<void> {
    // Ensure storage is initialized
    if (!this.storage) {
      this.storage = new CollectionsOAuthStorage(this.ctx.storage.sql)
    }

    try {
      // Run cleanup of expired tokens and codes
      const result = await this.storage.cleanup()
      console.log(`Cleanup completed: removed ${result.authCodes} expired auth codes, ${result.accessTokens} expired access tokens`)
    } catch (error) {
      console.error('Cleanup alarm failed:', error)
    }

    // Schedule the next alarm
    await this.ctx.storage.setAlarm(Date.now() + CLEANUP_ALARM_INTERVAL_MS)
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
