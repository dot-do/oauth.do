/**
 * Collections-based OAuth Storage
 *
 * Uses @dotdo/collections for document storage instead of raw SQL.
 * This eliminates the need for schema migrations - collections handle
 * all schema management internally with a single _collections table.
 *
 * @module storage-collections
 */

import { createCollection, initCollectionsSchema } from '@dotdo/collections'
import type { SyncCollection } from '@dotdo/collections/types'
import type { OAuthStorage } from './storage.js'
import type {
  OAuthUser,
  OAuthClient,
  OAuthAuthorizationCode,
  OAuthAccessToken,
  OAuthRefreshToken,
  OAuthGrant,
  OAuthOrganization,
} from './types.js'

/**
 * Document types with string IDs for collections.
 * Using intersection with Record<string, unknown> for index signature compatibility.
 */
type UserDoc = Omit<OAuthUser, 'id'> & { id: string } & Record<string, unknown>
type ClientDoc = Omit<OAuthClient, 'clientId'> & { clientId: string } & Record<string, unknown>
type AuthCodeDoc = Omit<OAuthAuthorizationCode, 'code'> & { code: string } & Record<string, unknown>
type AccessTokenDoc = Omit<OAuthAccessToken, 'token'> & { token: string } & Record<string, unknown>
type RefreshTokenDoc = Omit<OAuthRefreshToken, 'token'> & { token: string } & Record<string, unknown>
type GrantDoc = Omit<OAuthGrant, 'id'> & { id: string } & Record<string, unknown>
type OrganizationDoc = Omit<OAuthOrganization, 'id'> & { id: string } & Record<string, unknown>

/**
 * Collections-based OAuth storage implementation
 *
 * Uses document collections for flexible schema-less storage:
 * - users: User profiles from upstream auth
 * - clients: OAuth clients (apps)
 * - authCodes: Short-lived authorization codes
 * - accessTokens: Access token metadata (for opaque tokens)
 * - refreshTokens: Refresh tokens for token rotation
 * - grants: User consent grants
 *
 * @example
 * ```typescript
 * import { CollectionsOAuthStorage } from '@dotdo/oauth'
 *
 * export class OAuthDO extends DurableObject {
 *   private storage: CollectionsOAuthStorage
 *
 *   constructor(ctx: DurableObjectState, env: Env) {
 *     super(ctx, env)
 *     this.storage = new CollectionsOAuthStorage(ctx.storage.sql)
 *   }
 * }
 * ```
 */
export class CollectionsOAuthStorage implements OAuthStorage {
  private users: SyncCollection<UserDoc>
  private clients: SyncCollection<ClientDoc>
  private authCodes: SyncCollection<AuthCodeDoc>
  private accessTokens: SyncCollection<AccessTokenDoc>
  private refreshTokens: SyncCollection<RefreshTokenDoc>
  private grants: SyncCollection<GrantDoc>
  private organizations: SyncCollection<OrganizationDoc>

  constructor(sql: SqlStorage) {
    // Initialize collections schema (single table for all collections)
    initCollectionsSchema(sql)

    // Create typed collections
    this.users = createCollection<UserDoc>(sql, 'oauth:users')
    this.clients = createCollection<ClientDoc>(sql, 'oauth:clients')
    this.authCodes = createCollection<AuthCodeDoc>(sql, 'oauth:authCodes')
    this.accessTokens = createCollection<AccessTokenDoc>(sql, 'oauth:accessTokens')
    this.refreshTokens = createCollection<RefreshTokenDoc>(sql, 'oauth:refreshTokens')
    this.grants = createCollection<GrantDoc>(sql, 'oauth:grants')
    this.organizations = createCollection<OrganizationDoc>(sql, 'oauth:organizations')
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // User Operations
  // ═══════════════════════════════════════════════════════════════════════════

  async getUser(id: string): Promise<OAuthUser | null> {
    const doc = this.users.get(id)
    return doc ? { ...doc, id: doc.id } : null
  }

  async getUserByEmail(email: string): Promise<OAuthUser | null> {
    const docs = this.users.find({ email: email.toLowerCase() }, { limit: 1 })
    const doc = docs[0]
    return doc ? { ...doc, id: doc.id } : null
  }

  async saveUser(user: OAuthUser): Promise<void> {
    const doc = {
      ...user,
      id: user.id,
      email: user.email?.toLowerCase() || '',
    } as UserDoc
    this.users.put(user.id, doc)
  }

  async getUserByProvider(provider: string, providerId: string): Promise<OAuthUser | null> {
    // Look for user with matching provider and providerId fields
    const docs = this.users.find({ provider, providerId }, { limit: 1 })
    const doc = docs[0]
    return doc ? { ...doc, id: doc.id } : null
  }

  async deleteUser(id: string): Promise<void> {
    this.users.delete(id)
  }

  async listUsers(options?: { limit?: number; offset?: number }): Promise<OAuthUser[]> {
    const queryOptions: { limit?: number; offset?: number; sort?: string } = { sort: '-createdAt' }
    if (options?.limit !== undefined) queryOptions.limit = options.limit
    if (options?.offset !== undefined) queryOptions.offset = options.offset
    const docs = this.users.list(queryOptions)
    return docs.map((doc) => ({ ...doc, id: doc.id }))
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Organization Operations
  // ═══════════════════════════════════════════════════════════════════════════

  async getOrganization(id: string): Promise<OAuthOrganization | null> {
    const doc = this.organizations.get(id)
    return doc ? { ...doc, id: doc.id } : null
  }

  async getOrganizationBySlug(slug: string): Promise<OAuthOrganization | null> {
    const docs = this.organizations.find({ slug }, { limit: 1 })
    const doc = docs[0]
    return doc ? { ...doc, id: doc.id } : null
  }

  async getOrganizationByDomain(domain: string): Promise<OAuthOrganization | null> {
    // Search for organization with this domain in their domains array
    // Note: This is a simple implementation - for production, consider indexing
    const allOrgs = this.organizations.list()
    for (const doc of allOrgs) {
      if (doc.domains?.includes(domain.toLowerCase())) {
        return { ...doc, id: doc.id }
      }
    }
    return null
  }

  async saveOrganization(org: OAuthOrganization): Promise<void> {
    const doc = {
      ...org,
      id: org.id,
      domains: org.domains?.map((d) => d.toLowerCase()) ?? [],
    } as OrganizationDoc
    this.organizations.put(org.id, doc)
  }

  async deleteOrganization(id: string): Promise<void> {
    this.organizations.delete(id)
  }

  async listOrganizations(options?: { limit?: number; offset?: number }): Promise<OAuthOrganization[]> {
    const queryOptions: { limit?: number; offset?: number; sort?: string } = { sort: '-createdAt' }
    if (options?.limit !== undefined) queryOptions.limit = options.limit
    if (options?.offset !== undefined) queryOptions.offset = options.offset
    const docs = this.organizations.list(queryOptions)
    return docs.map((doc) => ({ ...doc, id: doc.id }))
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Client Operations
  // ═══════════════════════════════════════════════════════════════════════════

  async getClient(clientId: string): Promise<OAuthClient | null> {
    const doc = this.clients.get(clientId)
    return doc ? { ...doc, clientId: doc.clientId } : null
  }

  async saveClient(client: OAuthClient): Promise<void> {
    const doc = {
      ...client,
      clientId: client.clientId,
    } as ClientDoc
    this.clients.put(client.clientId, doc)
  }

  async deleteClient(clientId: string): Promise<void> {
    this.clients.delete(clientId)
  }

  async listClients(options?: { limit?: number; offset?: number }): Promise<OAuthClient[]> {
    const queryOptions: { limit?: number; offset?: number; sort?: string } = { sort: '-createdAt' }
    if (options?.limit !== undefined) queryOptions.limit = options.limit
    if (options?.offset !== undefined) queryOptions.offset = options.offset
    const docs = this.clients.list(queryOptions)
    return docs.map((doc) => ({ ...doc, clientId: doc.clientId }))
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Authorization Code Operations
  // ═══════════════════════════════════════════════════════════════════════════

  async saveAuthorizationCode(code: OAuthAuthorizationCode): Promise<void> {
    const doc = {
      ...code,
      code: code.code,
    } as AuthCodeDoc
    this.authCodes.put(code.code, doc)
  }

  async consumeAuthorizationCode(code: string): Promise<OAuthAuthorizationCode | null> {
    const doc = this.authCodes.get(code)
    if (!doc) return null

    // Delete the code (one-time use)
    this.authCodes.delete(code)

    return { ...doc, code: doc.code }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Access Token Operations
  // ═══════════════════════════════════════════════════════════════════════════

  async saveAccessToken(token: OAuthAccessToken): Promise<void> {
    const doc = {
      ...token,
      token: token.token,
    } as AccessTokenDoc
    this.accessTokens.put(token.token, doc)
  }

  async getAccessToken(token: string): Promise<OAuthAccessToken | null> {
    const doc = this.accessTokens.get(token)
    return doc ? { ...doc, token: doc.token } : null
  }

  async revokeAccessToken(token: string): Promise<void> {
    this.accessTokens.delete(token)
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Refresh Token Operations
  // ═══════════════════════════════════════════════════════════════════════════

  async saveRefreshToken(token: OAuthRefreshToken): Promise<void> {
    const doc = {
      ...token,
      token: token.token,
    } as RefreshTokenDoc
    this.refreshTokens.put(token.token, doc)
  }

  async getRefreshToken(token: string): Promise<OAuthRefreshToken | null> {
    const doc = this.refreshTokens.get(token)
    return doc ? { ...doc, token: doc.token } : null
  }

  async revokeRefreshToken(token: string): Promise<void> {
    const doc = this.refreshTokens.get(token)
    if (doc) {
      this.refreshTokens.put(token, { ...doc, revoked: true })
    }
  }

  async revokeAllUserTokens(userId: string): Promise<void> {
    // Find and revoke all refresh tokens for user
    const tokens = this.refreshTokens.find({ userId })
    for (const token of tokens) {
      this.refreshTokens.put(token.token, { ...token, revoked: true })
    }

    // Delete all access tokens for user
    const accessTokens = this.accessTokens.find({ userId })
    for (const token of accessTokens) {
      this.accessTokens.delete(token.token)
    }
  }

  async revokeAllClientTokens(clientId: string): Promise<void> {
    // Find and revoke all refresh tokens for client
    const tokens = this.refreshTokens.find({ clientId })
    for (const token of tokens) {
      this.refreshTokens.put(token.token, { ...token, revoked: true })
    }

    // Delete all access tokens for client
    const accessTokens = this.accessTokens.find({ clientId })
    for (const token of accessTokens) {
      this.accessTokens.delete(token.token)
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Grant Operations
  // ═══════════════════════════════════════════════════════════════════════════

  async getGrant(userId: string, clientId: string): Promise<OAuthGrant | null> {
    const id = `${userId}:${clientId}`
    const doc = this.grants.get(id)
    return doc ? { ...doc, id: doc.id } : null
  }

  async saveGrant(grant: OAuthGrant): Promise<void> {
    const id = grant.id || `${grant.userId}:${grant.clientId}`
    const doc = {
      ...grant,
      id,
    } as GrantDoc
    this.grants.put(id, doc)
  }

  async revokeGrant(userId: string, clientId: string): Promise<void> {
    const id = `${userId}:${clientId}`
    this.grants.delete(id)
  }

  async listUserGrants(userId: string): Promise<OAuthGrant[]> {
    const docs = this.grants.find({ userId })
    return docs.map((doc) => ({ ...doc, id: doc.id }))
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Cleanup Operations
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Clean up expired tokens and codes.
   * Call this periodically (e.g., via cron or alarm) to free storage.
   */
  async cleanup(): Promise<{ authCodes: number; accessTokens: number }> {
    const now = Date.now()

    // Find and delete expired auth codes
    const expiredCodes = this.authCodes.find({ expiresAt: { $lt: now } })
    for (const code of expiredCodes) {
      this.authCodes.delete(code.code)
    }

    // Find and delete expired access tokens
    const expiredTokens = this.accessTokens.find({ expiresAt: { $lt: now } })
    for (const token of expiredTokens) {
      this.accessTokens.delete(token.token)
    }

    return {
      authCodes: expiredCodes.length,
      accessTokens: expiredTokens.length,
    }
  }
}
