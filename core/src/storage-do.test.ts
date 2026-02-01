import { describe, it, expect, vi, beforeEach } from 'vitest'
import { DOSQLiteStorage, SqlStorage, SqlStorageResult } from './storage-do.js'

// ─────────────────────────────────────────────────────────────────────────────
// Mock SqlStorage
// ─────────────────────────────────────────────────────────────────────────────

interface ExecCall {
  query: string
  bindings: unknown[]
}

function createMockResult<T = Record<string, unknown>>(rows: T[] = []): SqlStorageResult<T> {
  return {
    toArray: () => rows,
    raw: () => rows as unknown as unknown[][],
    columnNames: [],
    rowsRead: rows.length,
    rowsWritten: 0,
  }
}

function createMockSql(selectResults: Record<string, unknown[]> = {}) {
  const calls: ExecCall[] = []

  const sql: SqlStorage = {
    exec<T = Record<string, unknown>>(query: string, ...bindings: unknown[]): SqlStorageResult<T> {
      calls.push({ query, bindings })

      // Match SELECT queries to provided results
      for (const [pattern, rows] of Object.entries(selectResults)) {
        if (query.includes(pattern)) {
          return createMockResult(rows as T[])
        }
      }

      return createMockResult<T>([])
    },
  }

  return { sql, calls }
}

// Helper to create storage without caring about schema init calls, then reset calls
function createStorage(selectResults: Record<string, unknown[]> = {}) {
  const { sql, calls } = createMockSql(selectResults)
  const storage = new DOSQLiteStorage(sql)
  const schemaCalls = [...calls]
  calls.length = 0 // reset so tests only see post-init calls
  return { storage, sql, calls, schemaCalls }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test Data
// ─────────────────────────────────────────────────────────────────────────────

const now = Date.now()

const userRow = {
  id: 'user-1',
  email: 'test@example.com',
  name: 'Test User',
  organization_id: 'org-1',
  provider: 'github',
  provider_id: 'gh-123',
  roles: '["admin"]',
  permissions: '["read","write"]',
  metadata: '{"key":"value"}',
  stripe_customer_id: 'cus_123',
  created_at: now,
  updated_at: now,
  last_login_at: now,
}

const orgRow = {
  id: 'org-1',
  name: 'Test Org',
  slug: 'test-org',
  domains: '["example.com","test.com"]',
  metadata: '{"plan":"pro"}',
  created_at: now,
  updated_at: now,
}

const clientRow = {
  client_id: 'client-1',
  client_secret_hash: 'hash123',
  client_name: 'Test App',
  redirect_uris: '["https://example.com/callback"]',
  grant_types: '["authorization_code"]',
  response_types: '["code"]',
  token_endpoint_auth_method: 'client_secret_basic',
  scope: 'openid profile',
  metadata: '{"env":"test"}',
  created_at: now,
  expires_at: now + 86400000,
}

const authCodeRow = {
  code: 'auth-code-1',
  client_id: 'client-1',
  user_id: 'user-1',
  redirect_uri: 'https://example.com/callback',
  scope: 'openid',
  code_challenge: 'challenge123',
  code_challenge_method: 'S256',
  state: 'state123',
  upstream_state: 'up-state',
  effective_issuer: 'https://issuer.example.com',
  issued_at: now,
  expires_at: now + 600000,
}

const accessTokenRow = {
  token: 'at-1',
  token_type: 'Bearer',
  client_id: 'client-1',
  user_id: 'user-1',
  scope: 'openid',
  issued_at: now,
  expires_at: now + 3600000,
}

const refreshTokenRow = {
  token: 'rt-1',
  client_id: 'client-1',
  user_id: 'user-1',
  scope: 'openid',
  issued_at: now,
  expires_at: now + 86400000,
  revoked: 0,
}

const grantRow = {
  id: 'grant-1',
  user_id: 'user-1',
  client_id: 'client-1',
  scope: 'openid',
  created_at: now,
  last_used_at: now,
  revoked: 0,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

describe('DOSQLiteStorage', () => {
  describe('Schema initialization', () => {
    it('creates all required tables on construction', () => {
      const { schemaCalls } = createStorage()
      const schemaQueries = schemaCalls.map((c) => c.query)

      expect(schemaQueries.some((q) => q.includes('CREATE TABLE IF NOT EXISTS users'))).toBe(true)
      expect(schemaQueries.some((q) => q.includes('CREATE TABLE IF NOT EXISTS organizations'))).toBe(true)
      expect(schemaQueries.some((q) => q.includes('CREATE TABLE IF NOT EXISTS oauth_clients'))).toBe(true)
      expect(schemaQueries.some((q) => q.includes('CREATE TABLE IF NOT EXISTS auth_codes'))).toBe(true)
      expect(schemaQueries.some((q) => q.includes('CREATE TABLE IF NOT EXISTS access_tokens'))).toBe(true)
      expect(schemaQueries.some((q) => q.includes('CREATE TABLE IF NOT EXISTS refresh_tokens'))).toBe(true)
      expect(schemaQueries.some((q) => q.includes('CREATE TABLE IF NOT EXISTS grants'))).toBe(true)
      expect(schemaQueries.some((q) => q.includes('CREATE TABLE IF NOT EXISTS signing_keys'))).toBe(true)
    })

    it('creates all required indexes on construction', () => {
      const { schemaCalls } = createStorage()
      const schemaQueries = schemaCalls.map((c) => c.query)

      expect(schemaQueries.some((q) => q.includes('idx_users_email'))).toBe(true)
      expect(schemaQueries.some((q) => q.includes('idx_users_provider'))).toBe(true)
      expect(schemaQueries.some((q) => q.includes('idx_users_stripe'))).toBe(true)
      expect(schemaQueries.some((q) => q.includes('idx_organizations_slug'))).toBe(true)
      expect(schemaQueries.some((q) => q.includes('idx_auth_codes_expires'))).toBe(true)
      expect(schemaQueries.some((q) => q.includes('idx_access_tokens_user'))).toBe(true)
      expect(schemaQueries.some((q) => q.includes('idx_access_tokens_client'))).toBe(true)
      expect(schemaQueries.some((q) => q.includes('idx_refresh_tokens_user'))).toBe(true)
      expect(schemaQueries.some((q) => q.includes('idx_refresh_tokens_client'))).toBe(true)
      expect(schemaQueries.some((q) => q.includes('idx_grants_user'))).toBe(true)
    })

    it('does not pass any bindings for schema DDL statements', () => {
      const { schemaCalls } = createStorage()
      for (const call of schemaCalls) {
        expect(call.bindings).toEqual([])
      }
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // User Operations
  // ═══════════════════════════════════════════════════════════════════════════

  describe('User Operations', () => {
    it('getUser returns user when found', async () => {
      const { storage, calls } = createStorage({ 'SELECT * FROM users WHERE id = ?': [userRow] })
      const user = await storage.getUser('user-1')

      expect(user).not.toBeNull()
      expect(user!.id).toBe('user-1')
      expect(user!.email).toBe('test@example.com')
      expect(user!.name).toBe('Test User')
      expect(user!.organizationId).toBe('org-1')
      expect(user!.provider).toBe('github')
      expect(user!.providerId).toBe('gh-123')
      expect(user!.roles).toEqual(['admin'])
      expect(user!.permissions).toEqual(['read', 'write'])
      expect(user!.metadata).toEqual({ key: 'value' })
      expect((user as any).stripeCustomerId).toBe('cus_123')
      expect(user!.createdAt).toBe(now)
      expect(user!.updatedAt).toBe(now)
      expect(user!.lastLoginAt).toBe(now)

      expect(calls[0].query).toContain('SELECT * FROM users WHERE id = ?')
      expect(calls[0].bindings).toEqual(['user-1'])
    })

    it('getUser returns null when not found', async () => {
      const { storage } = createStorage()
      const user = await storage.getUser('nonexistent')
      expect(user).toBeNull()
    })

    it('getUserByEmail lowercases email and uses parameterized query', async () => {
      const { storage, calls } = createStorage({ 'SELECT * FROM users WHERE email = ?': [userRow] })
      await storage.getUserByEmail('TEST@EXAMPLE.COM')

      expect(calls[0].query).toContain('WHERE email = ?')
      expect(calls[0].bindings).toEqual(['test@example.com'])
    })

    it('getUserByProvider uses parameterized query with both params', async () => {
      const { storage, calls } = createStorage({ 'SELECT * FROM users WHERE provider = ? AND provider_id = ?': [userRow] })
      await storage.getUserByProvider('github', 'gh-123')

      expect(calls[0].query).toContain('WHERE provider = ? AND provider_id = ?')
      expect(calls[0].bindings).toEqual(['github', 'gh-123'])
    })

    it('saveUser inserts user with all fields as bindings', async () => {
      const { storage, calls } = createStorage()
      await storage.saveUser({
        id: 'user-1',
        email: 'Test@Example.com',
        name: 'Test User',
        organizationId: 'org-1',
        provider: 'github',
        providerId: 'gh-123',
        roles: ['admin'],
        permissions: ['read', 'write'],
        metadata: { key: 'value' },
        createdAt: now,
        updatedAt: now,
        lastLoginAt: now,
      })

      expect(calls[0].query).toContain('INSERT OR REPLACE INTO users')
      expect(calls[0].query).toContain('VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
      expect(calls[0].bindings[0]).toBe('user-1')
      expect(calls[0].bindings[1]).toBe('test@example.com') // lowercased
      expect(calls[0].bindings[2]).toBe('Test User')
      expect(calls[0].bindings[3]).toBe('org-1')
      expect(calls[0].bindings[4]).toBe('github')
      expect(calls[0].bindings[5]).toBe('gh-123')
      expect(calls[0].bindings[6]).toBe('["admin"]')
      expect(calls[0].bindings[7]).toBe('["read","write"]')
      expect(calls[0].bindings[8]).toBe('{"key":"value"}')
      // bindings[9] is stripeCustomerId (null for regular user)
      expect(calls[0].bindings[10]).toBe(now)
      expect(calls[0].bindings[11]).toBe(now)
      expect(calls[0].bindings[12]).toBe(now)
    })

    it('saveUser handles optional fields as null', async () => {
      const { storage, calls } = createStorage()
      await storage.saveUser({
        id: 'user-2',
        createdAt: now,
        updatedAt: now,
      })

      expect(calls[0].bindings[1]).toBeNull() // email
      expect(calls[0].bindings[2]).toBeNull() // name
      expect(calls[0].bindings[3]).toBeNull() // organizationId
      expect(calls[0].bindings[6]).toBeNull() // roles
      expect(calls[0].bindings[7]).toBeNull() // permissions
      expect(calls[0].bindings[8]).toBeNull() // metadata
      expect(calls[0].bindings[12]).toBeNull() // lastLoginAt
    })

    it('deleteUser uses parameterized query', async () => {
      const { storage, calls } = createStorage()
      await storage.deleteUser('user-1')

      expect(calls[0].query).toContain('DELETE FROM users WHERE id = ?')
      expect(calls[0].bindings).toEqual(['user-1'])
    })

    it('listUsers returns all users without options', async () => {
      const { storage, calls } = createStorage({ 'SELECT * FROM users': [userRow] })
      const users = await storage.listUsers()

      expect(users).toHaveLength(1)
      expect(users[0].id).toBe('user-1')
      expect(calls[0].bindings).toEqual([])
    })

    it('listUsers filters by organizationId with parameterized query', async () => {
      const { storage, calls } = createStorage({ 'SELECT * FROM users': [userRow] })
      await storage.listUsers({ organizationId: 'org-1' })

      expect(calls[0].query).toContain('WHERE organization_id = ?')
      expect(calls[0].bindings).toContain('org-1')
    })

    it('listUsers applies limit with parameterized query', async () => {
      const { storage, calls } = createStorage()
      await storage.listUsers({ limit: 10 })

      expect(calls[0].query).toContain('LIMIT ?')
      expect(calls[0].bindings).toContain(10)
    })

    it('getUserByStripeCustomerId uses parameterized query', async () => {
      const { storage, calls } = createStorage({ 'SELECT * FROM users WHERE stripe_customer_id = ?': [userRow] })
      await storage.getUserByStripeCustomerId('cus_123')

      expect(calls[0].query).toContain('WHERE stripe_customer_id = ?')
      expect(calls[0].bindings).toEqual(['cus_123'])
    })

    it('updateUserStripeCustomerId uses parameterized query', async () => {
      const { storage, calls } = createStorage()
      await storage.updateUserStripeCustomerId('user-1', 'cus_456')

      expect(calls[0].query).toContain('UPDATE users SET stripe_customer_id = ?')
      expect(calls[0].bindings[0]).toBe('cus_456')
      expect(calls[0].bindings[2]).toBe('user-1')
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Organization Operations
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Organization Operations', () => {
    it('getOrganization returns org when found', async () => {
      const { storage, calls } = createStorage({ 'SELECT * FROM organizations WHERE id = ?': [orgRow] })
      const org = await storage.getOrganization('org-1')

      expect(org).not.toBeNull()
      expect(org!.id).toBe('org-1')
      expect(org!.name).toBe('Test Org')
      expect(org!.slug).toBe('test-org')
      expect(org!.domains).toEqual(['example.com', 'test.com'])
      expect(org!.metadata).toEqual({ plan: 'pro' })
      expect(calls[0].bindings).toEqual(['org-1'])
    })

    it('getOrganization returns null when not found', async () => {
      const { storage } = createStorage()
      expect(await storage.getOrganization('nope')).toBeNull()
    })

    it('getOrganizationBySlug lowercases slug', async () => {
      const { storage, calls } = createStorage({ 'SELECT * FROM organizations WHERE slug = ?': [orgRow] })
      await storage.getOrganizationBySlug('TEST-ORG')

      expect(calls[0].bindings).toEqual(['test-org'])
    })

    it('getOrganizationByDomain finds org matching domain (case-insensitive)', async () => {
      const { storage } = createStorage({ 'SELECT * FROM organizations WHERE domains IS NOT NULL': [orgRow] })
      const org = await storage.getOrganizationByDomain('EXAMPLE.COM')

      expect(org).not.toBeNull()
      expect(org!.id).toBe('org-1')
    })

    it('getOrganizationByDomain returns null when no match', async () => {
      const { storage } = createStorage({ 'SELECT * FROM organizations WHERE domains IS NOT NULL': [orgRow] })
      const org = await storage.getOrganizationByDomain('nomatch.com')
      expect(org).toBeNull()
    })

    it('saveOrganization inserts with all fields as bindings', async () => {
      const { storage, calls } = createStorage()
      await storage.saveOrganization({
        id: 'org-1',
        name: 'Test Org',
        slug: 'TEST-ORG',
        domains: ['example.com'],
        metadata: { plan: 'pro' },
        createdAt: now,
        updatedAt: now,
      })

      expect(calls[0].query).toContain('INSERT OR REPLACE INTO organizations')
      expect(calls[0].bindings[0]).toBe('org-1')
      expect(calls[0].bindings[1]).toBe('Test Org')
      expect(calls[0].bindings[2]).toBe('test-org') // lowercased
      expect(calls[0].bindings[3]).toBe('["example.com"]')
      expect(calls[0].bindings[4]).toBe('{"plan":"pro"}')
      expect(calls[0].bindings[5]).toBe(now)
      expect(calls[0].bindings[6]).toBe(now)
    })

    it('deleteOrganization uses parameterized query', async () => {
      const { storage, calls } = createStorage()
      await storage.deleteOrganization('org-1')

      expect(calls[0].query).toContain('DELETE FROM organizations WHERE id = ?')
      expect(calls[0].bindings).toEqual(['org-1'])
    })

    it('listOrganizations with limit uses parameterized query', async () => {
      const { storage, calls } = createStorage()
      await storage.listOrganizations({ limit: 5 })

      expect(calls[0].query).toContain('LIMIT ?')
      expect(calls[0].bindings).toEqual([5])
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Client Operations
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Client Operations', () => {
    it('getClient returns client when found', async () => {
      const { storage, calls } = createStorage({ 'SELECT * FROM oauth_clients WHERE client_id = ?': [clientRow] })
      const client = await storage.getClient('client-1')

      expect(client).not.toBeNull()
      expect(client!.clientId).toBe('client-1')
      expect(client!.clientSecretHash).toBe('hash123')
      expect(client!.clientName).toBe('Test App')
      expect(client!.redirectUris).toEqual(['https://example.com/callback'])
      expect(client!.grantTypes).toEqual(['authorization_code'])
      expect(client!.responseTypes).toEqual(['code'])
      expect(client!.tokenEndpointAuthMethod).toBe('client_secret_basic')
      expect(client!.scope).toBe('openid profile')
      expect(client!.metadata).toEqual({ env: 'test' })
      expect(calls[0].bindings).toEqual(['client-1'])
    })

    it('getClient returns null when not found', async () => {
      const { storage } = createStorage()
      expect(await storage.getClient('nope')).toBeNull()
    })

    it('saveClient inserts with all fields as bindings', async () => {
      const { storage, calls } = createStorage()
      await storage.saveClient({
        clientId: 'client-1',
        clientSecretHash: 'hash123',
        clientName: 'Test App',
        redirectUris: ['https://example.com/callback'],
        grantTypes: ['authorization_code'],
        responseTypes: ['code'],
        tokenEndpointAuthMethod: 'client_secret_basic',
        scope: 'openid profile',
        metadata: { env: 'test' },
        createdAt: now,
        expiresAt: now + 86400000,
      })

      expect(calls[0].query).toContain('INSERT OR REPLACE INTO oauth_clients')
      expect(calls[0].bindings[0]).toBe('client-1')
      expect(calls[0].bindings[1]).toBe('hash123')
      expect(calls[0].bindings[2]).toBe('Test App')
      expect(calls[0].bindings[3]).toBe('["https://example.com/callback"]')
      expect(calls[0].bindings[4]).toBe('["authorization_code"]')
      expect(calls[0].bindings[5]).toBe('["code"]')
      expect(calls[0].bindings[6]).toBe('client_secret_basic')
      expect(calls[0].bindings[7]).toBe('openid profile')
      expect(calls[0].bindings[8]).toBe('{"env":"test"}')
    })

    it('deleteClient uses parameterized query', async () => {
      const { storage, calls } = createStorage()
      await storage.deleteClient('client-1')

      expect(calls[0].query).toContain('DELETE FROM oauth_clients WHERE client_id = ?')
      expect(calls[0].bindings).toEqual(['client-1'])
    })

    it('listClients with limit', async () => {
      const { storage, calls } = createStorage({ 'SELECT * FROM oauth_clients': [clientRow] })
      const clients = await storage.listClients({ limit: 10 })

      expect(clients).toHaveLength(1)
      expect(calls[0].query).toContain('LIMIT ?')
      expect(calls[0].bindings).toEqual([10])
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Authorization Code Operations
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Authorization Code Operations', () => {
    it('saveAuthorizationCode inserts with all fields as bindings', async () => {
      const { storage, calls } = createStorage()
      await storage.saveAuthorizationCode({
        code: 'auth-code-1',
        clientId: 'client-1',
        userId: 'user-1',
        redirectUri: 'https://example.com/callback',
        scope: 'openid',
        codeChallenge: 'challenge123',
        codeChallengeMethod: 'S256',
        state: 'state123',
        upstreamState: 'up-state',
        effectiveIssuer: 'https://issuer.example.com',
        issuedAt: now,
        expiresAt: now + 600000,
      })

      expect(calls[0].query).toContain('INSERT OR REPLACE INTO auth_codes')
      expect(calls[0].query).toContain('VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
      expect(calls[0].bindings).toEqual([
        'auth-code-1',
        'client-1',
        'user-1',
        'https://example.com/callback',
        'openid',
        'challenge123',
        'S256',
        'state123',
        'up-state',
        'https://issuer.example.com',
        now,
        now + 600000,
      ])
    })

    it('consumeAuthorizationCode returns code and deletes it', async () => {
      const { storage, calls } = createStorage({ 'SELECT * FROM auth_codes WHERE code = ?': [authCodeRow] })
      const code = await storage.consumeAuthorizationCode('auth-code-1')

      expect(code).not.toBeNull()
      expect(code!.code).toBe('auth-code-1')
      expect(code!.clientId).toBe('client-1')
      expect(code!.userId).toBe('user-1')
      expect(code!.redirectUri).toBe('https://example.com/callback')
      expect(code!.codeChallenge).toBe('challenge123')
      expect(code!.codeChallengeMethod).toBe('S256')
      expect(code!.state).toBe('state123')
      expect(code!.upstreamState).toBe('up-state')
      expect(code!.effectiveIssuer).toBe('https://issuer.example.com')

      // First call: SELECT, second call: DELETE
      expect(calls[0].query).toContain('SELECT * FROM auth_codes WHERE code = ?')
      expect(calls[0].bindings).toEqual(['auth-code-1'])
      expect(calls[1].query).toContain('DELETE FROM auth_codes WHERE code = ?')
      expect(calls[1].bindings).toEqual(['auth-code-1'])
    })

    it('consumeAuthorizationCode returns null when not found', async () => {
      const { storage, calls } = createStorage()
      const code = await storage.consumeAuthorizationCode('nonexistent')

      expect(code).toBeNull()
      // Should NOT issue a DELETE when code not found
      expect(calls).toHaveLength(1) // only the SELECT
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Access Token Operations
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Access Token Operations', () => {
    it('saveAccessToken inserts with all fields as bindings', async () => {
      const { storage, calls } = createStorage()
      await storage.saveAccessToken({
        token: 'at-1',
        tokenType: 'Bearer',
        clientId: 'client-1',
        userId: 'user-1',
        scope: 'openid',
        issuedAt: now,
        expiresAt: now + 3600000,
      })

      expect(calls[0].query).toContain('INSERT OR REPLACE INTO access_tokens')
      expect(calls[0].bindings).toEqual([
        'at-1', 'Bearer', 'client-1', 'user-1', 'openid', now, now + 3600000,
      ])
    })

    it('getAccessToken returns token when found', async () => {
      const { storage, calls } = createStorage({ 'SELECT * FROM access_tokens WHERE token = ?': [accessTokenRow] })
      const token = await storage.getAccessToken('at-1')

      expect(token).not.toBeNull()
      expect(token!.token).toBe('at-1')
      expect(token!.tokenType).toBe('Bearer')
      expect(token!.clientId).toBe('client-1')
      expect(token!.userId).toBe('user-1')
      expect(token!.scope).toBe('openid')
      expect(calls[0].bindings).toEqual(['at-1'])
    })

    it('getAccessToken returns null when not found', async () => {
      const { storage } = createStorage()
      expect(await storage.getAccessToken('nope')).toBeNull()
    })

    it('revokeAccessToken deletes with parameterized query', async () => {
      const { storage, calls } = createStorage()
      await storage.revokeAccessToken('at-1')

      expect(calls[0].query).toContain('DELETE FROM access_tokens WHERE token = ?')
      expect(calls[0].bindings).toEqual(['at-1'])
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Refresh Token Operations
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Refresh Token Operations', () => {
    it('saveRefreshToken inserts with all fields as bindings', async () => {
      const { storage, calls } = createStorage()
      await storage.saveRefreshToken({
        token: 'rt-1',
        clientId: 'client-1',
        userId: 'user-1',
        scope: 'openid',
        issuedAt: now,
        expiresAt: now + 86400000,
        revoked: false,
      })

      expect(calls[0].query).toContain('INSERT OR REPLACE INTO refresh_tokens')
      expect(calls[0].bindings).toEqual([
        'rt-1', 'client-1', 'user-1', 'openid', now, now + 86400000, 0,
      ])
    })

    it('saveRefreshToken sets revoked to 1 when true', async () => {
      const { storage, calls } = createStorage()
      await storage.saveRefreshToken({
        token: 'rt-1',
        clientId: 'client-1',
        userId: 'user-1',
        issuedAt: now,
        revoked: true,
      })

      expect(calls[0].bindings[6]).toBe(1) // revoked = 1
    })

    it('getRefreshToken returns token when found', async () => {
      const { storage, calls } = createStorage({ 'SELECT * FROM refresh_tokens WHERE token = ?': [refreshTokenRow] })
      const token = await storage.getRefreshToken('rt-1')

      expect(token).not.toBeNull()
      expect(token!.token).toBe('rt-1')
      expect(token!.clientId).toBe('client-1')
      expect(token!.userId).toBe('user-1')
      expect(calls[0].bindings).toEqual(['rt-1'])
    })

    it('getRefreshToken returns null when not found', async () => {
      const { storage } = createStorage()
      expect(await storage.getRefreshToken('nope')).toBeNull()
    })

    it('revokeRefreshToken updates with parameterized query', async () => {
      const { storage, calls } = createStorage()
      await storage.revokeRefreshToken('rt-1')

      expect(calls[0].query).toContain('UPDATE refresh_tokens SET revoked = 1 WHERE token = ?')
      expect(calls[0].bindings).toEqual(['rt-1'])
    })

    it('revokeAllUserTokens deletes access tokens and revokes refresh tokens', async () => {
      const { storage, calls } = createStorage()
      await storage.revokeAllUserTokens('user-1')

      expect(calls[0].query).toContain('DELETE FROM access_tokens WHERE user_id = ?')
      expect(calls[0].bindings).toEqual(['user-1'])
      expect(calls[1].query).toContain('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?')
      expect(calls[1].bindings).toEqual(['user-1'])
    })

    it('revokeAllClientTokens deletes access tokens and revokes refresh tokens', async () => {
      const { storage, calls } = createStorage()
      await storage.revokeAllClientTokens('client-1')

      expect(calls[0].query).toContain('DELETE FROM access_tokens WHERE client_id = ?')
      expect(calls[0].bindings).toEqual(['client-1'])
      expect(calls[1].query).toContain('UPDATE refresh_tokens SET revoked = 1 WHERE client_id = ?')
      expect(calls[1].bindings).toEqual(['client-1'])
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Grant Operations
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Grant Operations', () => {
    it('getGrant returns grant when found', async () => {
      const { storage, calls } = createStorage({ 'SELECT * FROM grants WHERE user_id = ? AND client_id = ?': [grantRow] })
      const grant = await storage.getGrant('user-1', 'client-1')

      expect(grant).not.toBeNull()
      expect(grant!.id).toBe('grant-1')
      expect(grant!.userId).toBe('user-1')
      expect(grant!.clientId).toBe('client-1')
      expect(grant!.scope).toBe('openid')
      expect(calls[0].bindings).toEqual(['user-1', 'client-1'])
    })

    it('getGrant returns null when not found', async () => {
      const { storage } = createStorage()
      expect(await storage.getGrant('x', 'y')).toBeNull()
    })

    it('saveGrant inserts with all fields as bindings', async () => {
      const { storage, calls } = createStorage()
      await storage.saveGrant({
        id: 'grant-1',
        userId: 'user-1',
        clientId: 'client-1',
        scope: 'openid',
        createdAt: now,
        lastUsedAt: now,
        revoked: false,
      })

      expect(calls[0].query).toContain('INSERT OR REPLACE INTO grants')
      expect(calls[0].bindings).toEqual([
        'grant-1', 'user-1', 'client-1', 'openid', now, now, 0,
      ])
    })

    it('revokeGrant uses parameterized query', async () => {
      const { storage, calls } = createStorage()
      await storage.revokeGrant('user-1', 'client-1')

      expect(calls[0].query).toContain('UPDATE grants SET revoked = 1 WHERE user_id = ? AND client_id = ?')
      expect(calls[0].bindings).toEqual(['user-1', 'client-1'])
    })

    it('listUserGrants returns non-revoked grants', async () => {
      const { storage, calls } = createStorage({ 'SELECT * FROM grants WHERE user_id = ? AND revoked = 0': [grantRow] })
      const grants = await storage.listUserGrants('user-1')

      expect(grants).toHaveLength(1)
      expect(grants[0].id).toBe('grant-1')
      expect(calls[0].bindings).toEqual(['user-1'])
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Signing Key Operations
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Signing Key Operations', () => {
    const signingKeyRow = {
      kid: 'key-1',
      alg: 'RS256',
      private_key_jwk: '{"kty":"RSA"}',
      public_key_jwk: '{"kty":"RSA","e":"AQAB"}',
      created_at: now,
      is_current: 1,
    }

    it('getSigningKeys returns all keys', async () => {
      const { storage, calls } = createStorage({ 'SELECT * FROM signing_keys ORDER BY created_at DESC': [signingKeyRow] })
      const keys = await storage.getSigningKeys()

      expect(keys).toHaveLength(1)
      expect(keys[0].kid).toBe('key-1')
      expect(calls[0].bindings).toEqual([])
    })

    it('getCurrentSigningKey returns current key', async () => {
      const { storage, calls } = createStorage({ 'SELECT * FROM signing_keys WHERE is_current = 1': [signingKeyRow] })
      const key = await storage.getCurrentSigningKey()

      expect(key).not.toBeNull()
      expect(key!.kid).toBe('key-1')
      expect(calls[0].bindings).toEqual([])
    })

    it('getCurrentSigningKey returns null when none', async () => {
      const { storage } = createStorage()
      expect(await storage.getCurrentSigningKey()).toBeNull()
    })

    it('saveSigningKey unsets previous current and inserts', async () => {
      const { storage, calls } = createStorage()
      await storage.saveSigningKey({
        kid: 'key-1',
        alg: 'RS256',
        privateKeyJwk: { kty: 'RSA' } as JsonWebKey,
        publicKeyJwk: { kty: 'RSA', e: 'AQAB' } as JsonWebKey,
        createdAt: now,
        isCurrent: true,
      })

      // First call should unset previous current key
      expect(calls[0].query).toContain('UPDATE signing_keys SET is_current = 0')
      // Second call should insert
      expect(calls[1].query).toContain('INSERT OR REPLACE INTO signing_keys')
      expect(calls[1].bindings[0]).toBe('key-1')
      expect(calls[1].bindings[1]).toBe('RS256')
      expect(calls[1].bindings[4]).toBe(now)
      expect(calls[1].bindings[5]).toBe(1) // is_current
    })

    it('saveSigningKey skips unsetting current when isCurrent is false', async () => {
      const { storage, calls } = createStorage()
      await storage.saveSigningKey({
        kid: 'key-2',
        alg: 'RS256',
        privateKeyJwk: { kty: 'RSA' } as JsonWebKey,
        publicKeyJwk: { kty: 'RSA' } as JsonWebKey,
        createdAt: now,
        isCurrent: false,
      })

      // Should only have one call (no unset)
      expect(calls).toHaveLength(1)
      expect(calls[0].query).toContain('INSERT OR REPLACE INTO signing_keys')
      expect(calls[0].bindings[5]).toBe(0)
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // SQL Parameterization Safety
  // ═══════════════════════════════════════════════════════════════════════════

  describe('SQL Parameterization Safety', () => {
    it('never interpolates user input into query strings', async () => {
      const malicious = "'; DROP TABLE users; --"
      const { storage, calls } = createStorage()

      await storage.getUser(malicious)
      await storage.getUserByEmail(malicious)
      await storage.getUserByProvider(malicious, malicious)
      await storage.deleteUser(malicious)
      await storage.getClient(malicious)
      await storage.deleteClient(malicious)
      await storage.getAccessToken(malicious)
      await storage.revokeAccessToken(malicious)
      await storage.getRefreshToken(malicious)
      await storage.revokeRefreshToken(malicious)
      await storage.getOrganization(malicious)
      await storage.getOrganizationBySlug(malicious)
      await storage.consumeAuthorizationCode(malicious)
      await storage.revokeAllUserTokens(malicious)
      await storage.revokeAllClientTokens(malicious)
      await storage.getGrant(malicious, malicious)
      await storage.revokeGrant(malicious, malicious)
      await storage.listUserGrants(malicious)
      await storage.getUserByStripeCustomerId(malicious)
      await storage.updateUserStripeCustomerId(malicious, malicious)

      for (const call of calls) {
        // The malicious string should NEVER appear in the query itself
        expect(call.query).not.toContain(malicious)
        // But it should appear in bindings (possibly lowercased for email/slug)
      }
    })

    it('all user-provided values go through bindings, not template literals', async () => {
      const { storage, calls } = createStorage()
      await storage.saveUser({
        id: 'test-id',
        email: 'a@b.com',
        name: 'Name',
        createdAt: now,
        updatedAt: now,
      })

      const insertCall = calls[0]
      // The query should only contain ? placeholders, not actual values
      expect(insertCall.query).not.toContain('test-id')
      expect(insertCall.query).not.toContain('a@b.com')
      expect(insertCall.query).not.toContain("'Name'")
      // Values should be in bindings
      expect(insertCall.bindings).toContain('test-id')
      expect(insertCall.bindings).toContain('a@b.com')
      expect(insertCall.bindings).toContain('Name')
    })
  })
})
