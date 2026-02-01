import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { Hono } from 'hono'
import * as jose from 'jose'
import { auth, requireAuth, apiKey, type AuthUser } from '../src/hono.js'

// Mock jose module
vi.mock('jose', async () => {
  const actual = await vi.importActual<typeof import('jose')>('jose')
  return {
    ...actual,
    jwtVerify: vi.fn(),
    createRemoteJWKSet: vi.fn(() => vi.fn()),
  }
})

// Mock the global caches API (Cloudflare Workers Cache API)
const mockCacheStorage = new Map<string, Response>()
const mockCache = {
  match: vi.fn(async (request: Request) => {
    const cached = mockCacheStorage.get(request.url)
    if (cached) {
      // Return a clone so the original can still be read
      return cached.clone()
    }
    return undefined
  }),
  put: vi.fn(async (request: Request, response: Response) => {
    mockCacheStorage.set(request.url, response.clone())
  }),
  delete: vi.fn(async () => true),
}

// Set up global caches
;(globalThis as any).caches = {
  default: mockCache,
}

// Test user data
const mockUser: AuthUser = {
  id: 'user_123',
  email: 'test@example.com',
  name: 'Test User',
  organizationId: 'org_456',
  roles: ['admin', 'user'],
  permissions: ['read', 'write', 'delete'],
}

const mockJwtPayload = {
  sub: mockUser.id,
  email: mockUser.email,
  name: mockUser.name,
  org_id: mockUser.organizationId,
  roles: mockUser.roles,
  permissions: mockUser.permissions,
  aud: 'client_01JQYTRXK9ZPD8JPJTKDCRB656',
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
}

describe('hono middleware', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockCacheStorage.clear()

    // Reset jose mocks
    vi.mocked(jose.jwtVerify).mockReset()
    vi.mocked(jose.createRemoteJWKSet).mockReset()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // auth() middleware tests
  // ═══════════════════════════════════════════════════════════════════════════

  describe('auth() middleware', () => {
    it('should set user to null when no token provided', async () => {
      const app = new Hono()
      app.use('*', auth({ jwksUri: 'https://example.com/.well-known/jwks.json' }))
      app.get('/test', (c) => {
        return c.json({
          user: c.var.user,
          userId: c.var.userId,
          isAuth: c.var.isAuth,
          token: c.var.token,
        })
      })

      const res = await app.request('/test')
      const data = await res.json()

      expect(data.user).toBeNull()
      expect(data.userId).toBeNull()
      expect(data.isAuth).toBe(false)
      expect(data.token).toBeNull()
    })

    it('should extract token from Authorization header (Bearer format)', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: mockJwtPayload,
        protectedHeader: { alg: 'RS256' },
      } as any)

      const app = new Hono()
      app.use('*', auth({ jwksUri: 'https://example.com/.well-known/jwks.json' }))
      app.get('/test', (c) => {
        return c.json({
          user: c.var.user,
          token: c.var.token,
        })
      })

      const res = await app.request('/test', {
        headers: {
          Authorization: 'Bearer valid-jwt-token',
        },
      })
      const data = await res.json()

      expect(data.token).toBe('valid-jwt-token')
      expect(data.user).not.toBeNull()
      expect(data.user.id).toBe(mockUser.id)
    })

    it('should extract token from cookie', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: mockJwtPayload,
        protectedHeader: { alg: 'RS256' },
      } as any)

      const app = new Hono()
      app.use('*', auth({ jwksUri: 'https://example.com/.well-known/jwks.json' }))
      app.get('/test', (c) => {
        return c.json({
          user: c.var.user,
          token: c.var.token,
        })
      })

      const res = await app.request('/test', {
        headers: {
          Cookie: 'auth=cookie-jwt-token',
        },
      })
      const data = await res.json()

      expect(data.token).toBe('cookie-jwt-token')
      expect(data.user).not.toBeNull()
    })

    it('should use custom cookie name when specified', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: mockJwtPayload,
        protectedHeader: { alg: 'RS256' },
      } as any)

      const app = new Hono()
      app.use('*', auth({ cookieName: 'custom_auth', jwksUri: 'https://example.com/.well-known/jwks.json' }))
      app.get('/test', (c) => {
        return c.json({
          token: c.var.token,
        })
      })

      const res = await app.request('/test', {
        headers: {
          Cookie: 'custom_auth=custom-cookie-token',
        },
      })
      const data = await res.json()

      expect(data.token).toBe('custom-cookie-token')
    })

    it('should verify JWT and set user on context', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: mockJwtPayload,
        protectedHeader: { alg: 'RS256' },
      } as any)

      const app = new Hono()
      app.use('*', auth({ jwksUri: 'https://example.com/.well-known/jwks.json' }))
      app.get('/test', (c) => {
        return c.json({
          user: c.var.user,
          userId: c.var.userId,
          isAuth: c.var.isAuth,
        })
      })

      const res = await app.request('/test', {
        headers: {
          Authorization: 'Bearer valid-jwt-token',
        },
      })
      const data = await res.json()

      expect(data.user).toEqual({
        id: mockUser.id,
        email: mockUser.email,
        name: mockUser.name,
        organizationId: mockUser.organizationId,
        roles: mockUser.roles,
        permissions: mockUser.permissions,
        metadata: undefined,
      })
      expect(data.userId).toBe(mockUser.id)
      expect(data.isAuth).toBe(true)
    })

    it('should reject invalid JWT (leaves user as null)', async () => {
      vi.mocked(jose.jwtVerify).mockRejectedValueOnce(new Error('Invalid JWT'))

      const app = new Hono()
      app.use('*', auth({ jwksUri: 'https://example.com/.well-known/jwks.json' }))
      app.get('/test', (c) => {
        return c.json({
          user: c.var.user,
          userId: c.var.userId,
          isAuth: c.var.isAuth,
          token: c.var.token,
        })
      })

      const res = await app.request('/test', {
        headers: {
          Authorization: 'Bearer invalid-jwt-token',
        },
      })
      const data = await res.json()

      expect(data.user).toBeNull()
      expect(data.userId).toBeNull()
      expect(data.isAuth).toBe(false)
      // Token is still set even if verification fails
      expect(data.token).toBe('invalid-jwt-token')
    })

    it('should cache verified users', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValue({
        payload: mockJwtPayload,
        protectedHeader: { alg: 'RS256' },
      } as any)

      const app = new Hono()
      app.use('*', auth({ jwksUri: 'https://example.com/.well-known/jwks.json' }))
      app.get('/test', (c) => {
        return c.json({ user: c.var.user })
      })

      // First request - should call jwtVerify and cache
      await app.request('/test', {
        headers: { Authorization: 'Bearer cached-token' },
      })

      expect(vi.mocked(jose.jwtVerify)).toHaveBeenCalledTimes(1)
      expect(mockCache.put).toHaveBeenCalled()

      // Second request - should use cache
      vi.mocked(jose.jwtVerify).mockClear()

      await app.request('/test', {
        headers: { Authorization: 'Bearer cached-token' },
      })

      // jwtVerify should not be called again because the result is cached
      expect(vi.mocked(jose.jwtVerify)).not.toHaveBeenCalled()
    })

    it('should skip auth when skip function returns true', async () => {
      const app = new Hono()
      app.use(
        '*',
        auth({
          jwksUri: 'https://example.com/.well-known/jwks.json',
          skip: (c) => c.req.path === '/public',
        })
      )
      app.get('/public', (c) => {
        return c.json({
          user: c.var.user,
          isAuth: c.var.isAuth,
        })
      })

      const res = await app.request('/public', {
        headers: { Authorization: 'Bearer some-token' },
      })
      const data = await res.json()

      // Even with a token, auth is skipped
      expect(data.user).toBeNull()
      expect(data.isAuth).toBe(false)
      expect(vi.mocked(jose.jwtVerify)).not.toHaveBeenCalled()
    })

    it('should prefer Authorization header over cookie', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: mockJwtPayload,
        protectedHeader: { alg: 'RS256' },
      } as any)

      const app = new Hono()
      app.use('*', auth({ jwksUri: 'https://example.com/.well-known/jwks.json' }))
      app.get('/test', (c) => {
        return c.json({ token: c.var.token })
      })

      const res = await app.request('/test', {
        headers: {
          Authorization: 'Bearer header-token',
          Cookie: 'auth=cookie-token',
        },
      })
      const data = await res.json()

      expect(data.token).toBe('header-token')
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // requireAuth() middleware tests
  // ═══════════════════════════════════════════════════════════════════════════

  describe('requireAuth() middleware', () => {
    it('should return 401 when not authenticated', async () => {
      const app = new Hono()
      app.use('*', auth({ jwksUri: 'https://example.com/.well-known/jwks.json' }))
      app.use('/api/*', requireAuth({ jwksUri: 'https://example.com/.well-known/jwks.json' }))
      app.get('/api/protected', (c) => {
        return c.json({ success: true })
      })

      const res = await app.request('/api/protected')

      expect(res.status).toBe(401)
      const data = await res.json()
      expect(data.error).toBe('Authentication required')
    })

    it('should redirect when redirectTo option is set', async () => {
      const app = new Hono()
      app.use('*', auth({ jwksUri: 'https://example.com/.well-known/jwks.json' }))
      app.use('/api/*', requireAuth({ redirectTo: '/login' }))
      app.get('/api/protected', (c) => {
        return c.json({ success: true })
      })

      const res = await app.request('/api/protected')

      expect(res.status).toBe(302)
      expect(res.headers.get('Location')).toBe('/login')
    })

    it('should return 403 when missing required role', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: {
          ...mockJwtPayload,
          roles: ['user'], // Only has 'user' role
        },
        protectedHeader: { alg: 'RS256' },
      } as any)

      const app = new Hono()
      app.use('*', auth({ jwksUri: 'https://example.com/.well-known/jwks.json' }))
      app.use('/admin/*', requireAuth({ roles: ['admin', 'superadmin'] }))
      app.get('/admin/dashboard', (c) => {
        return c.json({ success: true })
      })

      const res = await app.request('/admin/dashboard', {
        headers: { Authorization: 'Bearer valid-token' },
      })

      expect(res.status).toBe(403)
      const data = await res.json()
      expect(data.error).toBe('Insufficient permissions')
    })

    it('should return 403 when missing required permission', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: {
          ...mockJwtPayload,
          permissions: ['read'], // Only has 'read' permission
        },
        protectedHeader: { alg: 'RS256' },
      } as any)

      const app = new Hono()
      app.use('*', auth({ jwksUri: 'https://example.com/.well-known/jwks.json' }))
      app.use('/api/*', requireAuth({ permissions: ['read', 'write'] }))
      app.get('/api/data', (c) => {
        return c.json({ success: true })
      })

      const res = await app.request('/api/data', {
        headers: { Authorization: 'Bearer valid-token' },
      })

      expect(res.status).toBe(403)
      const data = await res.json()
      expect(data.error).toBe('Insufficient permissions')
    })

    it('should allow through when authenticated with correct roles', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: {
          ...mockJwtPayload,
          roles: ['admin', 'user'],
        },
        protectedHeader: { alg: 'RS256' },
      } as any)

      const app = new Hono()
      app.use('*', auth({ jwksUri: 'https://example.com/.well-known/jwks.json' }))
      app.use('/admin/*', requireAuth({ roles: ['admin'] }))
      app.get('/admin/dashboard', (c) => {
        return c.json({ success: true, user: c.var.user })
      })

      const res = await app.request('/admin/dashboard', {
        headers: { Authorization: 'Bearer valid-token' },
      })

      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.success).toBe(true)
      expect(data.user).not.toBeNull()
    })

    it('should allow through when authenticated with correct permissions', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: {
          ...mockJwtPayload,
          permissions: ['read', 'write', 'delete'],
        },
        protectedHeader: { alg: 'RS256' },
      } as any)

      const app = new Hono()
      app.use('*', auth({ jwksUri: 'https://example.com/.well-known/jwks.json' }))
      app.use('/api/*', requireAuth({ permissions: ['read', 'write'] }))
      app.get('/api/data', (c) => {
        return c.json({ success: true })
      })

      const res = await app.request('/api/data', {
        headers: { Authorization: 'Bearer valid-token' },
      })

      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.success).toBe(true)
    })

    it('should allow any role from the list (OR logic)', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: {
          ...mockJwtPayload,
          roles: ['moderator'], // Has 'moderator', not 'admin'
        },
        protectedHeader: { alg: 'RS256' },
      } as any)

      const app = new Hono()
      app.use('*', auth({ jwksUri: 'https://example.com/.well-known/jwks.json' }))
      app.use('/admin/*', requireAuth({ roles: ['admin', 'moderator'] }))
      app.get('/admin/dashboard', (c) => {
        return c.json({ success: true })
      })

      const res = await app.request('/admin/dashboard', {
        headers: { Authorization: 'Bearer valid-token' },
      })

      expect(res.status).toBe(200)
    })

    it('should require all permissions (AND logic)', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: {
          ...mockJwtPayload,
          permissions: ['read', 'delete'], // Missing 'write'
        },
        protectedHeader: { alg: 'RS256' },
      } as any)

      const app = new Hono()
      app.use('*', auth({ jwksUri: 'https://example.com/.well-known/jwks.json' }))
      app.use('/api/*', requireAuth({ permissions: ['read', 'write', 'delete'] }))
      app.get('/api/data', (c) => {
        return c.json({ success: true })
      })

      const res = await app.request('/api/data', {
        headers: { Authorization: 'Bearer valid-token' },
      })

      expect(res.status).toBe(403)
    })

    it('should run auth middleware if not already done', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: mockJwtPayload,
        protectedHeader: { alg: 'RS256' },
      } as any)

      const app = new Hono()
      // Not using auth() middleware, only requireAuth({ jwksUri: 'https://example.com/.well-known/jwks.json' })
      app.use('/api/*', requireAuth({ jwksUri: 'https://example.com/.well-known/jwks.json' }))
      app.get('/api/protected', (c) => {
        return c.json({ success: true, user: c.var.user })
      })

      const res = await app.request('/api/protected', {
        headers: { Authorization: 'Bearer valid-token' },
      })

      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.user).not.toBeNull()
    })

    it('should handle user with no roles or permissions', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: {
          sub: 'user_123',
          email: 'test@example.com',
          // No roles or permissions
        },
        protectedHeader: { alg: 'RS256' },
      } as any)

      const app = new Hono()
      app.use('*', auth({ jwksUri: 'https://example.com/.well-known/jwks.json' }))
      app.use('/admin/*', requireAuth({ roles: ['admin'] }))
      app.get('/admin/dashboard', (c) => {
        return c.json({ success: true })
      })

      const res = await app.request('/admin/dashboard', {
        headers: { Authorization: 'Bearer valid-token' },
      })

      expect(res.status).toBe(403)
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // apiKey() middleware tests
  // ═══════════════════════════════════════════════════════════════════════════

  describe('apiKey() middleware', () => {
    const mockVerify = vi.fn<(key: string, c: any) => Promise<AuthUser | null>>()

    beforeEach(() => {
      mockVerify.mockReset()
    })

    it('should return 401 when no API key provided', async () => {
      const app = new Hono()
      app.use('/api/*', apiKey({ verify: mockVerify }))
      app.get('/api/data', (c) => {
        return c.json({ success: true })
      })

      const res = await app.request('/api/data')

      expect(res.status).toBe(401)
      const data = await res.json()
      expect(data.error).toBe('API key required')
    })

    it('should return 401 for invalid API key', async () => {
      mockVerify.mockResolvedValueOnce(null)

      const app = new Hono()
      app.use('/api/*', apiKey({ verify: mockVerify }))
      app.get('/api/data', (c) => {
        return c.json({ success: true })
      })

      const res = await app.request('/api/data', {
        headers: { 'X-API-Key': 'invalid-key' },
      })

      expect(res.status).toBe(401)
      const data = await res.json()
      expect(data.error).toBe('Invalid API key')
      expect(mockVerify).toHaveBeenCalledWith('invalid-key', expect.anything())
    })

    it('should set user when valid API key', async () => {
      mockVerify.mockResolvedValueOnce(mockUser)

      const app = new Hono()
      app.use('/api/*', apiKey({ verify: mockVerify }))
      app.get('/api/data', (c) => {
        return c.json({
          success: true,
          user: c.var.user,
          userId: c.var.userId,
          isAuth: c.var.isAuth,
          token: c.var.token,
        })
      })

      const res = await app.request('/api/data', {
        headers: { 'X-API-Key': 'valid-api-key' },
      })

      expect(res.status).toBe(200)
      const data = await res.json()
      expect(data.success).toBe(true)
      expect(data.user).toEqual(mockUser)
      expect(data.userId).toBe(mockUser.id)
      expect(data.isAuth).toBe(true)
      expect(data.token).toBe('valid-api-key')
    })

    it('should use custom header name when specified', async () => {
      mockVerify.mockResolvedValueOnce(mockUser)

      const app = new Hono()
      app.use(
        '/api/*',
        apiKey({
          headerName: 'Authorization',
          verify: mockVerify,
        })
      )
      app.get('/api/data', (c) => {
        return c.json({ success: true })
      })

      const res = await app.request('/api/data', {
        headers: { Authorization: 'api_key_12345' },
      })

      expect(res.status).toBe(200)
      expect(mockVerify).toHaveBeenCalledWith('api_key_12345', expect.anything())
    })

    it('should pass context to verify function', async () => {
      mockVerify.mockImplementation(async (key, c) => {
        // Verify that context is passed correctly
        if (c.req.path === '/api/data') {
          return mockUser
        }
        return null
      })

      const app = new Hono()
      app.use('/api/*', apiKey({ verify: mockVerify }))
      app.get('/api/data', (c) => {
        return c.json({ success: true })
      })

      const res = await app.request('/api/data', {
        headers: { 'X-API-Key': 'valid-key' },
      })

      expect(res.status).toBe(200)
    })
  })
})
