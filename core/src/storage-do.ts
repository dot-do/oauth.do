/**
 * @dotdo/oauth - Durable Object SQLite Storage
 *
 * SQLite-based storage adapter for Cloudflare Durable Objects.
 * Implements the OAuthStorage interface for persistent storage.
 */

import type { OAuthStorage, ListOptions } from './storage.js'
import type {
  OAuthUser,
  OAuthOrganization,
  OAuthClient,
  OAuthAuthorizationCode,
  OAuthAccessToken,
  OAuthRefreshToken,
  OAuthGrant,
  OAuthDeviceCode,
} from './types.js'

/**
 * Cloudflare Durable Object SqlStorage interface
 * This matches the Cloudflare Workers runtime API
 */
export interface SqlStorage {
  exec<T = Record<string, unknown>>(query: string, ...bindings: unknown[]): SqlStorageResult<T>
}

export interface SqlStorageResult<T> {
  toArray(): T[]
  raw<R = unknown[]>(): R[]
  columnNames: string[]
  rowsRead: number
  rowsWritten: number
}

/**
 * Extended user type with Stripe integration
 */
export interface OAuthUserWithStripe extends OAuthUser {
  stripeCustomerId?: string
}

/**
 * DO SQLite Storage implementation
 */
export class DOSQLiteStorage implements OAuthStorage {
  constructor(private sql: SqlStorage) {
    this.initSchema()
  }

  /**
   * Initialize database schema
   */
  private initSchema(): void {
    // Users table with Stripe integration
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE,
        name TEXT,
        organization_id TEXT,
        provider TEXT,
        provider_id TEXT,
        roles TEXT,
        permissions TEXT,
        metadata TEXT,
        stripe_customer_id TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        last_login_at INTEGER
      )
    `)

    // Organizations table
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS organizations (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        slug TEXT UNIQUE,
        domains TEXT,
        metadata TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      )
    `)

    // OAuth clients table
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS oauth_clients (
        client_id TEXT PRIMARY KEY,
        client_secret_hash TEXT,
        client_name TEXT NOT NULL,
        redirect_uris TEXT NOT NULL,
        grant_types TEXT NOT NULL,
        response_types TEXT NOT NULL,
        token_endpoint_auth_method TEXT NOT NULL,
        scope TEXT,
        metadata TEXT,
        created_at INTEGER NOT NULL,
        expires_at INTEGER
      )
    `)

    // Authorization codes table
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS auth_codes (
        code TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        redirect_uri TEXT NOT NULL,
        scope TEXT,
        code_challenge TEXT,
        code_challenge_method TEXT,
        state TEXT,
        upstream_state TEXT,
        effective_issuer TEXT,
        issued_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      )
    `)

    // Access tokens table
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS access_tokens (
        token TEXT PRIMARY KEY,
        token_type TEXT NOT NULL,
        client_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        scope TEXT,
        issued_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      )
    `)

    // Refresh tokens table
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS refresh_tokens (
        token TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        scope TEXT,
        issued_at INTEGER NOT NULL,
        expires_at INTEGER,
        revoked INTEGER DEFAULT 0
      )
    `)

    // Grants table
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS grants (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        client_id TEXT NOT NULL,
        scope TEXT,
        created_at INTEGER NOT NULL,
        last_used_at INTEGER,
        revoked INTEGER DEFAULT 0,
        UNIQUE(user_id, client_id)
      )
    `)

    // Device codes table (RFC 8628)
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS device_codes (
        device_code TEXT PRIMARY KEY,
        user_code TEXT NOT NULL UNIQUE,
        client_id TEXT NOT NULL,
        scope TEXT,
        issued_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        interval_secs INTEGER NOT NULL DEFAULT 5,
        user_id TEXT,
        authorized INTEGER DEFAULT 0,
        denied INTEGER DEFAULT 0,
        effective_issuer TEXT,
        last_poll_time INTEGER
      )
    `)

    // Signing keys table (for JWT signing)
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS signing_keys (
        kid TEXT PRIMARY KEY,
        alg TEXT NOT NULL,
        private_key_jwk TEXT NOT NULL,
        public_key_jwk TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        is_current INTEGER DEFAULT 0
      )
    `)

    // Create indexes
    this.sql.exec(`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`)
    this.sql.exec(`CREATE INDEX IF NOT EXISTS idx_users_provider ON users(provider, provider_id)`)
    this.sql.exec(`CREATE INDEX IF NOT EXISTS idx_users_stripe ON users(stripe_customer_id)`)
    this.sql.exec(`CREATE INDEX IF NOT EXISTS idx_organizations_slug ON organizations(slug)`)
    this.sql.exec(`CREATE INDEX IF NOT EXISTS idx_auth_codes_expires ON auth_codes(expires_at)`)
    this.sql.exec(`CREATE INDEX IF NOT EXISTS idx_access_tokens_user ON access_tokens(user_id)`)
    this.sql.exec(`CREATE INDEX IF NOT EXISTS idx_access_tokens_client ON access_tokens(client_id)`)
    this.sql.exec(`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id)`)
    this.sql.exec(`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_client ON refresh_tokens(client_id)`)
    this.sql.exec(`CREATE INDEX IF NOT EXISTS idx_grants_user ON grants(user_id)`)
    this.sql.exec(`CREATE INDEX IF NOT EXISTS idx_device_codes_user_code ON device_codes(user_code)`)
    this.sql.exec(`CREATE INDEX IF NOT EXISTS idx_device_codes_expires ON device_codes(expires_at)`)
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // User Operations
  // ═══════════════════════════════════════════════════════════════════════════

  async getUser(id: string): Promise<OAuthUser | null> {
    const row = this.sql.exec<UserRow>('SELECT * FROM users WHERE id = ?', id).toArray()[0] ?? null
    return row ? this.rowToUser(row) : null
  }

  async getUserByEmail(email: string): Promise<OAuthUser | null> {
    const row = this.sql.exec<UserRow>('SELECT * FROM users WHERE email = ?', email.toLowerCase()).toArray()[0] ?? null
    return row ? this.rowToUser(row) : null
  }

  async getUserByProvider(provider: string, providerId: string): Promise<OAuthUser | null> {
    const row = this.sql.exec<UserRow>(
      'SELECT * FROM users WHERE provider = ? AND provider_id = ?',
      provider,
      providerId
    ).toArray()[0] ?? null
    return row ? this.rowToUser(row) : null
  }

  async saveUser(user: OAuthUser): Promise<void> {
    const userWithStripe = user as OAuthUserWithStripe
    this.sql.exec(
      `INSERT OR REPLACE INTO users
       (id, email, name, organization_id, provider, provider_id, roles, permissions, metadata, stripe_customer_id, created_at, updated_at, last_login_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      user.id,
      user.email?.toLowerCase() ?? null,
      user.name ?? null,
      user.organizationId ?? null,
      user.provider ?? null,
      user.providerId ?? null,
      user.roles ? JSON.stringify(user.roles) : null,
      user.permissions ? JSON.stringify(user.permissions) : null,
      user.metadata ? JSON.stringify(user.metadata) : null,
      userWithStripe.stripeCustomerId ?? null,
      user.createdAt,
      user.updatedAt,
      user.lastLoginAt ?? null
    )
  }

  async deleteUser(id: string): Promise<void> {
    this.sql.exec('DELETE FROM users WHERE id = ?', id)
  }

  async listUsers(options?: ListOptions): Promise<OAuthUser[]> {
    let query = 'SELECT * FROM users'
    const params: unknown[] = []

    if (options?.organizationId) {
      query += ' WHERE organization_id = ?'
      params.push(options.organizationId)
    }

    if (options?.limit) {
      query += ' LIMIT ?'
      params.push(options.limit)
    }

    const rows = this.sql.exec<UserRow>(query, ...params).toArray()
    return rows.map((row) => this.rowToUser(row))
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Organization Operations
  // ═══════════════════════════════════════════════════════════════════════════

  async getOrganization(id: string): Promise<OAuthOrganization | null> {
    const row = this.sql.exec<OrgRow>('SELECT * FROM organizations WHERE id = ?', id).toArray()[0] ?? null
    return row ? this.rowToOrganization(row) : null
  }

  async getOrganizationBySlug(slug: string): Promise<OAuthOrganization | null> {
    const row = this.sql.exec<OrgRow>(
      'SELECT * FROM organizations WHERE slug = ?',
      slug.toLowerCase()
    ).toArray()[0] ?? null
    return row ? this.rowToOrganization(row) : null
  }

  async getOrganizationByDomain(domain: string): Promise<OAuthOrganization | null> {
    // Search for domain in the JSON array
    const rows = this.sql.exec<OrgRow>('SELECT * FROM organizations WHERE domains IS NOT NULL').toArray()
    for (const row of rows) {
      const domains = row.domains ? JSON.parse(row.domains) as string[] : []
      if (domains.some((d) => d.toLowerCase() === domain.toLowerCase())) {
        return this.rowToOrganization(row)
      }
    }
    return null
  }

  async saveOrganization(org: OAuthOrganization): Promise<void> {
    this.sql.exec(
      `INSERT OR REPLACE INTO organizations
       (id, name, slug, domains, metadata, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      org.id,
      org.name,
      org.slug?.toLowerCase() ?? null,
      org.domains ? JSON.stringify(org.domains) : null,
      org.metadata ? JSON.stringify(org.metadata) : null,
      org.createdAt,
      org.updatedAt
    )
  }

  async deleteOrganization(id: string): Promise<void> {
    this.sql.exec('DELETE FROM organizations WHERE id = ?', id)
  }

  async listOrganizations(options?: ListOptions): Promise<OAuthOrganization[]> {
    let query = 'SELECT * FROM organizations'
    const params: unknown[] = []

    if (options?.limit) {
      query += ' LIMIT ?'
      params.push(options.limit)
    }

    const rows = this.sql.exec<OrgRow>(query, ...params).toArray()
    return rows.map((row) => this.rowToOrganization(row))
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Client Operations
  // ═══════════════════════════════════════════════════════════════════════════

  async getClient(clientId: string): Promise<OAuthClient | null> {
    const row = this.sql.exec<ClientRow>('SELECT * FROM oauth_clients WHERE client_id = ?', clientId).toArray()[0] ?? null
    return row ? this.rowToClient(row) : null
  }

  async saveClient(client: OAuthClient): Promise<void> {
    this.sql.exec(
      `INSERT OR REPLACE INTO oauth_clients
       (client_id, client_secret_hash, client_name, redirect_uris, grant_types, response_types, token_endpoint_auth_method, scope, metadata, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      client.clientId,
      client.clientSecretHash ?? null,
      client.clientName,
      JSON.stringify(client.redirectUris),
      JSON.stringify(client.grantTypes),
      JSON.stringify(client.responseTypes),
      client.tokenEndpointAuthMethod,
      client.scope ?? null,
      client.metadata ? JSON.stringify(client.metadata) : null,
      client.createdAt,
      client.expiresAt ?? null
    )
  }

  async deleteClient(clientId: string): Promise<void> {
    this.sql.exec('DELETE FROM oauth_clients WHERE client_id = ?', clientId)
  }

  async listClients(options?: ListOptions): Promise<OAuthClient[]> {
    let query = 'SELECT * FROM oauth_clients'
    const params: unknown[] = []

    if (options?.limit) {
      query += ' LIMIT ?'
      params.push(options.limit)
    }

    const rows = this.sql.exec<ClientRow>(query, ...params).toArray()
    return rows.map((row) => this.rowToClient(row))
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Authorization Code Operations
  // ═══════════════════════════════════════════════════════════════════════════

  async saveAuthorizationCode(code: OAuthAuthorizationCode): Promise<void> {
    this.sql.exec(
      `INSERT OR REPLACE INTO auth_codes
       (code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, state, upstream_state, effective_issuer, issued_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      code.code,
      code.clientId,
      code.userId,
      code.redirectUri,
      code.scope ?? null,
      code.codeChallenge ?? null,
      code.codeChallengeMethod ?? null,
      code.state ?? null,
      code.upstreamState ?? null,
      code.effectiveIssuer ?? null,
      code.issuedAt,
      code.expiresAt
    )
  }

  async consumeAuthorizationCode(code: string): Promise<OAuthAuthorizationCode | null> {
    const row = this.sql.exec<AuthCodeRow>('SELECT * FROM auth_codes WHERE code = ?', code).toArray()[0] ?? null
    if (!row) return null

    // Delete the code (one-time use)
    this.sql.exec('DELETE FROM auth_codes WHERE code = ?', code)

    return this.rowToAuthCode(row)
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Token Operations
  // ═══════════════════════════════════════════════════════════════════════════

  async saveAccessToken(token: OAuthAccessToken): Promise<void> {
    this.sql.exec(
      `INSERT OR REPLACE INTO access_tokens
       (token, token_type, client_id, user_id, scope, issued_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      token.token,
      token.tokenType,
      token.clientId,
      token.userId,
      token.scope ?? null,
      token.issuedAt,
      token.expiresAt
    )
  }

  async getAccessToken(token: string): Promise<OAuthAccessToken | null> {
    const row = this.sql.exec<AccessTokenRow>('SELECT * FROM access_tokens WHERE token = ?', token).toArray()[0] ?? null
    return row ? this.rowToAccessToken(row) : null
  }

  async revokeAccessToken(token: string): Promise<void> {
    this.sql.exec('DELETE FROM access_tokens WHERE token = ?', token)
  }

  async saveRefreshToken(token: OAuthRefreshToken): Promise<void> {
    this.sql.exec(
      `INSERT OR REPLACE INTO refresh_tokens
       (token, client_id, user_id, scope, issued_at, expires_at, revoked)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      token.token,
      token.clientId,
      token.userId,
      token.scope ?? null,
      token.issuedAt,
      token.expiresAt ?? null,
      token.revoked ? 1 : 0
    )
  }

  async getRefreshToken(token: string): Promise<OAuthRefreshToken | null> {
    const row = this.sql.exec<RefreshTokenRow>('SELECT * FROM refresh_tokens WHERE token = ?', token).toArray()[0] ?? null
    return row ? this.rowToRefreshToken(row) : null
  }

  async revokeRefreshToken(token: string): Promise<void> {
    this.sql.exec('UPDATE refresh_tokens SET revoked = 1 WHERE token = ?', token)
  }

  async revokeAllUserTokens(userId: string): Promise<void> {
    this.sql.exec('DELETE FROM access_tokens WHERE user_id = ?', userId)
    this.sql.exec('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?', userId)
  }

  async revokeAllClientTokens(clientId: string): Promise<void> {
    this.sql.exec('DELETE FROM access_tokens WHERE client_id = ?', clientId)
    this.sql.exec('UPDATE refresh_tokens SET revoked = 1 WHERE client_id = ?', clientId)
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Grant Operations
  // ═══════════════════════════════════════════════════════════════════════════

  async getGrant(userId: string, clientId: string): Promise<OAuthGrant | null> {
    const row = this.sql.exec<GrantRow>(
      'SELECT * FROM grants WHERE user_id = ? AND client_id = ?',
      userId,
      clientId
    ).toArray()[0] ?? null
    return row ? this.rowToGrant(row) : null
  }

  async saveGrant(grant: OAuthGrant): Promise<void> {
    this.sql.exec(
      `INSERT OR REPLACE INTO grants
       (id, user_id, client_id, scope, created_at, last_used_at, revoked)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      grant.id,
      grant.userId,
      grant.clientId,
      grant.scope ?? null,
      grant.createdAt,
      grant.lastUsedAt ?? null,
      grant.revoked ? 1 : 0
    )
  }

  async revokeGrant(userId: string, clientId: string): Promise<void> {
    this.sql.exec('UPDATE grants SET revoked = 1 WHERE user_id = ? AND client_id = ?', userId, clientId)
  }

  async listUserGrants(userId: string): Promise<OAuthGrant[]> {
    const rows = this.sql.exec<GrantRow>(
      'SELECT * FROM grants WHERE user_id = ? AND revoked = 0',
      userId
    ).toArray()
    return rows.map((row) => this.rowToGrant(row))
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Device Code Operations (RFC 8628)
  // ═══════════════════════════════════════════════════════════════════════════

  async saveDeviceCode(deviceCode: OAuthDeviceCode): Promise<void> {
    this.sql.exec(
      `INSERT OR REPLACE INTO device_codes
       (device_code, user_code, client_id, scope, issued_at, expires_at, interval_secs, user_id, authorized, denied, effective_issuer, last_poll_time)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      deviceCode.deviceCode,
      deviceCode.userCode.toUpperCase(),
      deviceCode.clientId,
      deviceCode.scope ?? null,
      deviceCode.issuedAt,
      deviceCode.expiresAt,
      deviceCode.interval,
      deviceCode.userId ?? null,
      deviceCode.authorized ? 1 : 0,
      deviceCode.denied ? 1 : 0,
      deviceCode.effectiveIssuer ?? null,
      deviceCode.lastPollTime ?? null
    )
  }

  async getDeviceCode(deviceCode: string): Promise<OAuthDeviceCode | null> {
    const row = this.sql.exec<DeviceCodeRow>(
      'SELECT * FROM device_codes WHERE device_code = ?',
      deviceCode
    ).toArray()[0] ?? null
    return row ? this.rowToDeviceCode(row) : null
  }

  async getDeviceCodeByUserCode(userCode: string): Promise<OAuthDeviceCode | null> {
    const row = this.sql.exec<DeviceCodeRow>(
      'SELECT * FROM device_codes WHERE user_code = ?',
      userCode.toUpperCase()
    ).toArray()[0] ?? null
    return row ? this.rowToDeviceCode(row) : null
  }

  async updateDeviceCode(deviceCode: OAuthDeviceCode): Promise<void> {
    this.sql.exec(
      `UPDATE device_codes SET
       user_id = ?, authorized = ?, denied = ?, last_poll_time = ?
       WHERE device_code = ?`,
      deviceCode.userId ?? null,
      deviceCode.authorized ? 1 : 0,
      deviceCode.denied ? 1 : 0,
      deviceCode.lastPollTime ?? null,
      deviceCode.deviceCode
    )
  }

  async deleteDeviceCode(deviceCode: string): Promise<void> {
    this.sql.exec('DELETE FROM device_codes WHERE device_code = ?', deviceCode)
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Signing Key Operations (for JWT signing)
  // ═══════════════════════════════════════════════════════════════════════════

  async getSigningKeys(): Promise<SerializedSigningKeyRow[]> {
    return this.sql.exec<SerializedSigningKeyRow>(
      'SELECT * FROM signing_keys ORDER BY created_at DESC'
    ).toArray()
  }

  async getCurrentSigningKey(): Promise<SerializedSigningKeyRow | null> {
    return this.sql.exec<SerializedSigningKeyRow>(
      'SELECT * FROM signing_keys WHERE is_current = 1'
    ).toArray()[0] ?? null
  }

  async saveSigningKey(key: {
    kid: string
    alg: string
    privateKeyJwk: JsonWebKey
    publicKeyJwk: JsonWebKey
    createdAt: number
    isCurrent?: boolean
  }): Promise<void> {
    // If this is the current key, unset previous current
    if (key.isCurrent) {
      this.sql.exec('UPDATE signing_keys SET is_current = 0')
    }

    this.sql.exec(
      `INSERT OR REPLACE INTO signing_keys
       (kid, alg, private_key_jwk, public_key_jwk, created_at, is_current)
       VALUES (?, ?, ?, ?, ?, ?)`,
      key.kid,
      key.alg,
      JSON.stringify(key.privateKeyJwk),
      JSON.stringify(key.publicKeyJwk),
      key.createdAt,
      key.isCurrent ? 1 : 0
    )
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Stripe Integration Helpers
  // ═══════════════════════════════════════════════════════════════════════════

  async getUserByStripeCustomerId(stripeCustomerId: string): Promise<OAuthUser | null> {
    const row = this.sql.exec<UserRow>(
      'SELECT * FROM users WHERE stripe_customer_id = ?',
      stripeCustomerId
    ).toArray()[0] ?? null
    return row ? this.rowToUser(row) : null
  }

  async updateUserStripeCustomerId(userId: string, stripeCustomerId: string): Promise<void> {
    this.sql.exec(
      'UPDATE users SET stripe_customer_id = ?, updated_at = ? WHERE id = ?',
      stripeCustomerId,
      Date.now(),
      userId
    )
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Row Type Conversions
  // ═══════════════════════════════════════════════════════════════════════════

  private rowToUser(row: UserRow): OAuthUserWithStripe {
    return {
      id: row.id,
      ...(row.email && { email: row.email }),
      ...(row.name && { name: row.name }),
      ...(row.organization_id && { organizationId: row.organization_id }),
      ...(row.provider && { provider: row.provider }),
      ...(row.provider_id && { providerId: row.provider_id }),
      ...(row.roles && { roles: JSON.parse(row.roles) }),
      ...(row.permissions && { permissions: JSON.parse(row.permissions) }),
      ...(row.metadata && { metadata: JSON.parse(row.metadata) }),
      ...(row.stripe_customer_id && { stripeCustomerId: row.stripe_customer_id }),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      ...(row.last_login_at && { lastLoginAt: row.last_login_at }),
    }
  }

  private rowToOrganization(row: OrgRow): OAuthOrganization {
    return {
      id: row.id,
      name: row.name,
      ...(row.slug && { slug: row.slug }),
      ...(row.domains && { domains: JSON.parse(row.domains) }),
      ...(row.metadata && { metadata: JSON.parse(row.metadata) }),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    }
  }

  private rowToClient(row: ClientRow): OAuthClient {
    return {
      clientId: row.client_id,
      ...(row.client_secret_hash && { clientSecretHash: row.client_secret_hash }),
      clientName: row.client_name,
      redirectUris: JSON.parse(row.redirect_uris),
      grantTypes: JSON.parse(row.grant_types),
      responseTypes: JSON.parse(row.response_types),
      tokenEndpointAuthMethod: row.token_endpoint_auth_method as OAuthClient['tokenEndpointAuthMethod'],
      ...(row.scope && { scope: row.scope }),
      ...(row.metadata && { metadata: JSON.parse(row.metadata) }),
      createdAt: row.created_at,
      ...(row.expires_at && { expiresAt: row.expires_at }),
    }
  }

  private rowToAuthCode(row: AuthCodeRow): OAuthAuthorizationCode {
    return {
      code: row.code,
      clientId: row.client_id,
      userId: row.user_id,
      redirectUri: row.redirect_uri,
      ...(row.scope && { scope: row.scope }),
      ...(row.code_challenge && { codeChallenge: row.code_challenge }),
      ...(row.code_challenge_method && { codeChallengeMethod: row.code_challenge_method as 'S256' }),
      ...(row.state && { state: row.state }),
      ...(row.upstream_state && { upstreamState: row.upstream_state }),
      ...(row.effective_issuer && { effectiveIssuer: row.effective_issuer }),
      issuedAt: row.issued_at,
      expiresAt: row.expires_at,
    }
  }

  private rowToAccessToken(row: AccessTokenRow): OAuthAccessToken {
    return {
      token: row.token,
      tokenType: row.token_type as 'Bearer',
      clientId: row.client_id,
      userId: row.user_id,
      ...(row.scope && { scope: row.scope }),
      issuedAt: row.issued_at,
      expiresAt: row.expires_at,
    }
  }

  private rowToRefreshToken(row: RefreshTokenRow): OAuthRefreshToken {
    return {
      token: row.token,
      clientId: row.client_id,
      userId: row.user_id,
      ...(row.scope && { scope: row.scope }),
      issuedAt: row.issued_at,
      ...(row.expires_at && { expiresAt: row.expires_at }),
      ...(row.revoked && { revoked: row.revoked === 1 }),
    }
  }

  private rowToGrant(row: GrantRow): OAuthGrant {
    return {
      id: row.id,
      userId: row.user_id,
      clientId: row.client_id,
      ...(row.scope && { scope: row.scope }),
      createdAt: row.created_at,
      ...(row.last_used_at && { lastUsedAt: row.last_used_at }),
      ...(row.revoked && { revoked: row.revoked === 1 }),
    }
  }

  private rowToDeviceCode(row: DeviceCodeRow): OAuthDeviceCode {
    return {
      deviceCode: row.device_code,
      userCode: row.user_code,
      clientId: row.client_id,
      ...(row.scope && { scope: row.scope }),
      issuedAt: row.issued_at,
      expiresAt: row.expires_at,
      interval: row.interval_secs,
      ...(row.user_id && { userId: row.user_id }),
      ...(row.authorized && { authorized: row.authorized === 1 }),
      ...(row.denied && { denied: row.denied === 1 }),
      ...(row.effective_issuer && { effectiveIssuer: row.effective_issuer }),
      ...(row.last_poll_time && { lastPollTime: row.last_poll_time }),
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Row Types (SQLite result shapes)
// ═══════════════════════════════════════════════════════════════════════════

interface UserRow {
  id: string
  email: string | null
  name: string | null
  organization_id: string | null
  provider: string | null
  provider_id: string | null
  roles: string | null
  permissions: string | null
  metadata: string | null
  stripe_customer_id: string | null
  created_at: number
  updated_at: number
  last_login_at: number | null
}

interface OrgRow {
  id: string
  name: string
  slug: string | null
  domains: string | null
  metadata: string | null
  created_at: number
  updated_at: number
}

interface ClientRow {
  client_id: string
  client_secret_hash: string | null
  client_name: string
  redirect_uris: string
  grant_types: string
  response_types: string
  token_endpoint_auth_method: string
  scope: string | null
  metadata: string | null
  created_at: number
  expires_at: number | null
}

interface AuthCodeRow {
  code: string
  client_id: string
  user_id: string
  redirect_uri: string
  scope: string | null
  code_challenge: string | null
  code_challenge_method: string | null
  state: string | null
  upstream_state: string | null
  effective_issuer: string | null
  issued_at: number
  expires_at: number
}

interface AccessTokenRow {
  token: string
  token_type: string
  client_id: string
  user_id: string
  scope: string | null
  issued_at: number
  expires_at: number
}

interface RefreshTokenRow {
  token: string
  client_id: string
  user_id: string
  scope: string | null
  issued_at: number
  expires_at: number | null
  revoked: number
}

interface GrantRow {
  id: string
  user_id: string
  client_id: string
  scope: string | null
  created_at: number
  last_used_at: number | null
  revoked: number
}

interface DeviceCodeRow {
  device_code: string
  user_code: string
  client_id: string
  scope: string | null
  issued_at: number
  expires_at: number
  interval_secs: number
  user_id: string | null
  authorized: number
  denied: number
  effective_issuer: string | null
  last_poll_time: number | null
}

export interface SerializedSigningKeyRow {
  kid: string
  alg: string
  private_key_jwk: string
  public_key_jwk: string
  created_at: number
  is_current: number
}
