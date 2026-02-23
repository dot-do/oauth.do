import { describe, it, expect, beforeEach } from 'vitest'
import { MemoryOAuthStorage } from 'id.org.ai/oauth'
import type { OAuthUser, OAuthOrganization, OAuthClient, OAuthAuthorizationCode, OAuthGrant } from 'id.org.ai/oauth'

describe('MemoryOAuthStorage', () => {
  let storage: MemoryOAuthStorage

  beforeEach(() => {
    storage = new MemoryOAuthStorage()
  })

  describe('User operations', () => {
    const testUser: OAuthUser = {
      id: 'user_123',
      email: 'test@example.com',
      name: 'Test User',
      organizationId: 'org_456',
      createdAt: Date.now(),
      updatedAt: Date.now(),
    }

    it('saves and retrieves user by id', async () => {
      await storage.saveUser(testUser)
      const retrieved = await storage.getUser('user_123')
      expect(retrieved).toEqual(testUser)
    })

    it('retrieves user by email', async () => {
      await storage.saveUser(testUser)
      const retrieved = await storage.getUserByEmail('test@example.com')
      expect(retrieved).toEqual(testUser)
    })

    it('email lookup is case-insensitive', async () => {
      await storage.saveUser(testUser)
      const retrieved = await storage.getUserByEmail('TEST@EXAMPLE.COM')
      expect(retrieved).toEqual(testUser)
    })

    it('returns null for non-existent user', async () => {
      const retrieved = await storage.getUser('nonexistent')
      expect(retrieved).toBeNull()
    })

    it('deletes user', async () => {
      await storage.saveUser(testUser)
      await storage.deleteUser('user_123')
      const retrieved = await storage.getUser('user_123')
      expect(retrieved).toBeNull()
    })

    it('lists users', async () => {
      await storage.saveUser(testUser)
      await storage.saveUser({ ...testUser, id: 'user_456', email: 'other@example.com' })
      const users = await storage.listUsers()
      expect(users).toHaveLength(2)
    })

    it('lists users with limit', async () => {
      await storage.saveUser(testUser)
      await storage.saveUser({ ...testUser, id: 'user_456', email: 'other@example.com' })
      const users = await storage.listUsers({ limit: 1 })
      expect(users).toHaveLength(1)
    })

    it('lists users filtered by organization', async () => {
      await storage.saveUser(testUser)
      await storage.saveUser({ ...testUser, id: 'user_456', email: 'other@example.com', organizationId: 'org_789' })
      const users = await storage.listUsers({ organizationId: 'org_456' })
      expect(users).toHaveLength(1)
      expect(users[0]?.id).toBe('user_123')
    })
  })

  describe('Organization operations', () => {
    const testOrg: OAuthOrganization = {
      id: 'org_123',
      name: 'Test Org',
      slug: 'test-org',
      createdAt: Date.now(),
      updatedAt: Date.now(),
    }

    it('saves and retrieves organization by id', async () => {
      await storage.saveOrganization(testOrg)
      const retrieved = await storage.getOrganization('org_123')
      expect(retrieved).toEqual(testOrg)
    })

    it('retrieves organization by slug', async () => {
      await storage.saveOrganization(testOrg)
      const retrieved = await storage.getOrganizationBySlug('test-org')
      expect(retrieved).toEqual(testOrg)
    })

    it('slug lookup is case-insensitive', async () => {
      await storage.saveOrganization(testOrg)
      const retrieved = await storage.getOrganizationBySlug('TEST-ORG')
      expect(retrieved).toEqual(testOrg)
    })

    it('deletes organization', async () => {
      await storage.saveOrganization(testOrg)
      await storage.deleteOrganization('org_123')
      const retrieved = await storage.getOrganization('org_123')
      expect(retrieved).toBeNull()
    })
  })

  describe('Client operations', () => {
    const testClient: OAuthClient = {
      clientId: 'client_123',
      clientSecretHash: 'hashed_secret',
      clientName: 'Test Client',
      redirectUris: ['https://example.com/callback'],
      grantTypes: ['authorization_code', 'refresh_token'],
      responseTypes: ['code'],
      tokenEndpointAuthMethod: 'client_secret_basic',
      createdAt: Date.now(),
    }

    it('saves and retrieves client', async () => {
      await storage.saveClient(testClient)
      const retrieved = await storage.getClient('client_123')
      expect(retrieved).toEqual(testClient)
    })

    it('deletes client', async () => {
      await storage.saveClient(testClient)
      await storage.deleteClient('client_123')
      const retrieved = await storage.getClient('client_123')
      expect(retrieved).toBeNull()
    })

    it('lists clients', async () => {
      await storage.saveClient(testClient)
      await storage.saveClient({ ...testClient, clientId: 'client_456' })
      const clients = await storage.listClients()
      expect(clients).toHaveLength(2)
    })
  })

  describe('Authorization code operations', () => {
    const testCode: OAuthAuthorizationCode = {
      code: 'auth_code_123',
      clientId: 'client_123',
      userId: 'user_123',
      redirectUri: 'https://example.com/callback',
      scope: 'openid profile',
      codeChallenge: 'challenge',
      codeChallengeMethod: 'S256',
      issuedAt: Date.now(),
      expiresAt: Date.now() + 600000,
    }

    it('saves and consumes authorization code', async () => {
      await storage.saveAuthorizationCode(testCode)
      const retrieved = await storage.consumeAuthorizationCode('auth_code_123')
      expect(retrieved).toEqual(testCode)
    })

    it('code can only be consumed once', async () => {
      await storage.saveAuthorizationCode(testCode)
      await storage.consumeAuthorizationCode('auth_code_123')
      const second = await storage.consumeAuthorizationCode('auth_code_123')
      expect(second).toBeNull()
    })

    it('returns null for non-existent code', async () => {
      const retrieved = await storage.consumeAuthorizationCode('nonexistent')
      expect(retrieved).toBeNull()
    })
  })

  describe('Token operations', () => {
    it('saves and retrieves access token', async () => {
      await storage.saveAccessToken({
        token: 'access_123',
        tokenType: 'Bearer',
        clientId: 'client_123',
        userId: 'user_123',
        scope: 'openid',
        issuedAt: Date.now(),
        expiresAt: Date.now() + 3600000,
      })
      const retrieved = await storage.getAccessToken('access_123')
      expect(retrieved?.token).toBe('access_123')
    })

    it('revokes access token', async () => {
      await storage.saveAccessToken({
        token: 'access_123',
        tokenType: 'Bearer',
        clientId: 'client_123',
        userId: 'user_123',
        issuedAt: Date.now(),
        expiresAt: Date.now() + 3600000,
      })
      await storage.revokeAccessToken('access_123')
      const retrieved = await storage.getAccessToken('access_123')
      expect(retrieved).toBeNull()
    })

    it('saves and retrieves refresh token', async () => {
      await storage.saveRefreshToken({
        token: 'refresh_123',
        clientId: 'client_123',
        userId: 'user_123',
        scope: 'openid',
        issuedAt: Date.now(),
      })
      const retrieved = await storage.getRefreshToken('refresh_123')
      expect(retrieved?.token).toBe('refresh_123')
    })

    it('revokes refresh token', async () => {
      await storage.saveRefreshToken({
        token: 'refresh_123',
        clientId: 'client_123',
        userId: 'user_123',
        issuedAt: Date.now(),
      })
      await storage.revokeRefreshToken('refresh_123')
      const retrieved = await storage.getRefreshToken('refresh_123')
      expect(retrieved?.revoked).toBe(true)
    })

    it('revokes all user tokens', async () => {
      await storage.saveAccessToken({
        token: 'access_123',
        tokenType: 'Bearer',
        clientId: 'client_123',
        userId: 'user_123',
        issuedAt: Date.now(),
        expiresAt: Date.now() + 3600000,
      })
      await storage.saveRefreshToken({
        token: 'refresh_123',
        clientId: 'client_123',
        userId: 'user_123',
        issuedAt: Date.now(),
      })
      await storage.revokeAllUserTokens('user_123')
      expect(await storage.getAccessToken('access_123')).toBeNull()
      expect((await storage.getRefreshToken('refresh_123'))?.revoked).toBe(true)
    })
  })

  describe('Grant operations', () => {
    const testGrant: OAuthGrant = {
      id: 'user_123:client_123',
      userId: 'user_123',
      clientId: 'client_123',
      scope: 'openid profile',
      createdAt: Date.now(),
    }

    it('saves and retrieves grant', async () => {
      await storage.saveGrant(testGrant)
      const retrieved = await storage.getGrant('user_123', 'client_123')
      expect(retrieved).toEqual(testGrant)
    })

    it('revokes grant', async () => {
      await storage.saveGrant(testGrant)
      await storage.revokeGrant('user_123', 'client_123')
      const retrieved = await storage.getGrant('user_123', 'client_123')
      expect(retrieved?.revoked).toBe(true)
    })

    it('lists user grants', async () => {
      const grant1: OAuthGrant = {
        id: 'user_123:client_123',
        userId: 'user_123',
        clientId: 'client_123',
        scope: 'openid',
        createdAt: Date.now(),
      }
      const grant2: OAuthGrant = {
        id: 'user_123:client_456',
        userId: 'user_123',
        clientId: 'client_456',
        scope: 'openid',
        createdAt: Date.now(),
      }
      await storage.saveGrant(grant1)
      await storage.saveGrant(grant2)
      const grants = await storage.listUserGrants('user_123')
      expect(grants).toHaveLength(2)
    })

    it('does not list revoked grants', async () => {
      await storage.saveGrant(testGrant)
      await storage.revokeGrant('user_123', 'client_123')
      const grants = await storage.listUserGrants('user_123')
      expect(grants).toHaveLength(0)
    })
  })

  describe('clear', () => {
    it('clears all data', async () => {
      await storage.saveUser({ id: 'user_123', email: 'test@example.com', createdAt: Date.now(), updatedAt: Date.now() })
      await storage.saveOrganization({ id: 'org_123', name: 'Test', createdAt: Date.now(), updatedAt: Date.now() })
      await storage.saveClient({
        clientId: 'client_123',
        clientName: 'Test',
        redirectUris: [],
        grantTypes: ['authorization_code'],
        responseTypes: ['code'],
        tokenEndpointAuthMethod: 'none',
        createdAt: Date.now(),
      })

      storage.clear()

      expect(await storage.getUser('user_123')).toBeNull()
      expect(await storage.getOrganization('org_123')).toBeNull()
      expect(await storage.getClient('client_123')).toBeNull()
    })
  })
})
