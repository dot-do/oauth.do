import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import * as jose from 'jose'
import {
  optionalAuth,
  requireAuth,
  apiKey,
  combined,
  getAuth,
  isAuthenticated,
  getUser,
  type AuthRequest,
  type AuthUser,
  type AuthContext,
} from '../src/itty.js'

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

// Helper to create mock Request objects
function createMockRequest(options: {
  url?: string
  headers?: Record<string, string>
} = {}): Request {
  const { url = 'https://example.com/test', headers = {} } = options
  return new Request(url, { headers })
}

describe('itty middleware', () => {
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
  // Helper functions tests
  // ═══════════════════════════════════════════════════════════════════════════

  describe('extractToken helper (via middleware)', () => {
    it('should extract token from Authorization header (Bearer format)', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: mockJwtPayload,
        protectedHeader: { alg: 'RS256' },
      } as any)

      const request = createMockRequest({
        headers: { Authorization: 'Bearer header-jwt-token' },
      })

      const middleware = optionalAuth({ jwksUri: 'https://example.com/.well-known/jwks.json' })
      await middleware(request)

      const authRequest = request as AuthRequest
      expect(authRequest.auth.token).toBe('header-jwt-token')
    })

    it('should extract token from cookie', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: mockJwtPayload,
        protectedHeader: { alg: 'RS256' },
      } as any)

      const request = createMockRequest({
        headers: { Cookie: 'auth=cookie-jwt-token' },
      })

      const middleware = optionalAuth({ jwksUri: 'https://example.com/.well-known/jwks.json' })
      await middleware(request)

      const authRequest = request as AuthRequest
      expect(authRequest.auth.token).toBe('cookie-jwt-token')
    })

    it('should use custom cookie name when specified', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: mockJwtPayload,
        protectedHeader: { alg: 'RS256' },
      } as any)

      const request = createMockRequest({
        headers: { Cookie: 'custom_auth=custom-cookie-token' },
      })

      const middleware = optionalAuth({
        cookieName: 'custom_auth',
        jwksUri: 'https://example.com/.well-known/jwks.json',
      })
      await middleware(request)

      const authRequest = request as AuthRequest
      expect(authRequest.auth.token).toBe('custom-cookie-token')
    })

    it('should prefer Authorization header over cookie', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: mockJwtPayload,
        protectedHeader: { alg: 'RS256' },
      } as any)

      const request = createMockRequest({
        headers: {
          Authorization: 'Bearer header-token',
          Cookie: 'auth=cookie-token',
        },
      })

      const middleware = optionalAuth({ jwksUri: 'https://example.com/.well-known/jwks.json' })
      await middleware(request)

      const authRequest = request as AuthRequest
      expect(authRequest.auth.token).toBe('header-token')
    })

    it('should return null when no token is present', async () => {
      const request = createMockRequest()

      const middleware = optionalAuth({ jwksUri: 'https://example.com/.well-known/jwks.json' })
      await middleware(request)

      const authRequest = request as AuthRequest
      expect(authRequest.auth.token).toBeNull()
    })

    it('should handle cookies with equals sign in value', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: mockJwtPayload,
        protectedHeader: { alg: 'RS256' },
      } as any)

      const request = createMockRequest({
        headers: { Cookie: 'auth=token=with=equals' },
      })

      const middleware = optionalAuth({ jwksUri: 'https://example.com/.well-known/jwks.json' })
      await middleware(request)

      const authRequest = request as AuthRequest
      expect(authRequest.auth.token).toBe('token=with=equals')
    })

    it('should handle multiple cookies', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: mockJwtPayload,
        protectedHeader: { alg: 'RS256' },
      } as any)

      const request = createMockRequest({
        headers: { Cookie: 'other=value; auth=correct-token; another=thing' },
      })

      const middleware = optionalAuth({ jwksUri: 'https://example.com/.well-known/jwks.json' })
      await middleware(request)

      const authRequest = request as AuthRequest
      expect(authRequest.auth.token).toBe('correct-token')
    })
  })

  describe('hashToken helper (via caching)', () => {
    it('should hash tokens consistently for cache keys', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValue({
        payload: mockJwtPayload,
        protectedHeader: { alg: 'RS256' },
      } as any)

      const request1 = createMockRequest({
        headers: { Authorization: 'Bearer same-token' },
      })
      const request2 = createMockRequest({
        headers: { Authorization: 'Bearer same-token' },
      })

      const middleware = optionalAuth({ jwksUri: 'https://example.com/.well-known/jwks.json' })

      // First request
      await middleware(request1)
      expect(mockCache.put).toHaveBeenCalledTimes(1)

      // Clear the jwtVerify mock to check if cache is used
      vi.mocked(jose.jwtVerify).mockClear()

      // Second request should use cache (same hash)
      await middleware(request2)
      expect(vi.mocked(jose.jwtVerify)).not.toHaveBeenCalled()
    })

    it('should produce different hashes for different tokens', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValue({
        payload: mockJwtPayload,
        protectedHeader: { alg: 'RS256' },
      } as any)

      const request1 = createMockRequest({
        headers: { Authorization: 'Bearer token-one' },
      })
      const request2 = createMockRequest({
        headers: { Authorization: 'Bearer token-two' },
      })

      const middleware = optionalAuth({ jwksUri: 'https://example.com/.well-known/jwks.json' })

      await middleware(request1)
      await middleware(request2)

      // Both requests should verify JWT because tokens are different
      expect(vi.mocked(jose.jwtVerify)).toHaveBeenCalledTimes(2)
    })
  })

  describe('Cache behavior', () => {
    it('should cache verified user', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: mockJwtPayload,
        protectedHeader: { alg: 'RS256' },
      } as any)

      const request = createMockRequest({
        headers: { Authorization: 'Bearer cached-token' },
      })

      const middleware = optionalAuth({ jwksUri: 'https://example.com/.well-known/jwks.json' })
      await middleware(request)

      expect(mockCache.put).toHaveBeenCalled()
      const putCall = mockCache.put.mock.calls[0]
      expect(putCall[0].url).toContain('https://oauth.do/_cache/token/')
    })

    it('should return cached user on second request', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: mockJwtPayload,
        protectedHeader: { alg: 'RS256' },
      } as any)

      const middleware = optionalAuth({ jwksUri: 'https://example.com/.well-known/jwks.json' })

      // First request
      const request1 = createMockRequest({
        headers: { Authorization: 'Bearer cached-token' },
      })
      await middleware(request1)
      expect(vi.mocked(jose.jwtVerify)).toHaveBeenCalledTimes(1)

      // Clear mock to check if cache is used
      vi.mocked(jose.jwtVerify).mockClear()

      // Second request
      const request2 = createMockRequest({
        headers: { Authorization: 'Bearer cached-token' },
      })
      await middleware(request2)

      // Should not call jwtVerify because result is cached
      expect(vi.mocked(jose.jwtVerify)).not.toHaveBeenCalled()
      expect((request2 as AuthRequest).auth.isAuth).toBe(true)
      expect((request2 as AuthRequest).auth.user?.id).toBe(mockUser.id)
    })

    it('should handle expired cache entries', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValue({
        payload: mockJwtPayload,
        protectedHeader: { alg: 'RS256' },
      } as any)

      // Create expired cache entry
      const expiredData = { user: mockUser, expiresAt: Date.now() - 1000 }
      const expiredResponse = new Response(JSON.stringify(expiredData), {
        headers: { 'Cache-Control': 'max-age=300' },
      })

      // Manually add expired entry to cache
      mockCache.match.mockImplementationOnce(async () => expiredResponse.clone())

      const request = createMockRequest({
        headers: { Authorization: 'Bearer expired-cache-token' },
      })

      const middleware = optionalAuth({ jwksUri: 'https://example.com/.well-known/jwks.json' })
      await middleware(request)

      // Should call jwtVerify because cache is expired
      expect(vi.mocked(jose.jwtVerify)).toHaveBeenCalled()
    })

    it('should handle cache errors gracefully', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: mockJwtPayload,
        protectedHeader: { alg: 'RS256' },
      } as any)

      // Make cache throw an error
      mockCache.match.mockRejectedValueOnce(new Error('Cache error'))

      const request = createMockRequest({
        headers: { Authorization: 'Bearer error-token' },
      })

      const middleware = optionalAuth({ jwksUri: 'https://example.com/.well-known/jwks.json' })
      await middleware(request)

      // Should still work by verifying JWT
      expect(vi.mocked(jose.jwtVerify)).toHaveBeenCalled()
      expect((request as AuthRequest).auth.isAuth).toBe(true)
    })

    it('should handle cache put errors gracefully', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: mockJwtPayload,
        protectedHeader: { alg: 'RS256' },
      } as any)

      // Make cache put throw an error
      mockCache.put.mockRejectedValueOnce(new Error('Cache put error'))

      const request = createMockRequest({
        headers: { Authorization: 'Bearer put-error-token' },
      })

      const middleware = optionalAuth({ jwksUri: 'https://example.com/.well-known/jwks.json' })
      await middleware(request)

      // Should still complete successfully even if cache fails
      expect((request as AuthRequest).auth.isAuth).toBe(true)
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // optionalAuth middleware tests
  // ═══════════════════════════════════════════════════════════════════════════

  describe('optionalAuth() middleware', () => {
    it('should set default auth context when no token provided', async () => {
      const request = createMockRequest()

      const middleware = optionalAuth({ jwksUri: 'https://example.com/.well-known/jwks.json' })
      await middleware(request)

      const authRequest = request as AuthRequest
      expect(authRequest.auth.user).toBeNull()
      expect(authRequest.auth.userId).toBeNull()
      expect(authRequest.auth.isAuth).toBe(false)
      expect(authRequest.auth.token).toBeNull()
    })

    it('should verify JWT and set user on request', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: mockJwtPayload,
        protectedHeader: { alg: 'RS256' },
      } as any)

      const request = createMockRequest({
        headers: { Authorization: 'Bearer valid-jwt-token' },
      })

      const middleware = optionalAuth({ jwksUri: 'https://example.com/.well-known/jwks.json' })
      await middleware(request)

      const authRequest = request as AuthRequest
      expect(authRequest.auth.user).toEqual({
        id: mockUser.id,
        email: mockUser.email,
        name: mockUser.name,
        organizationId: mockUser.organizationId,
        roles: mockUser.roles,
        permissions: mockUser.permissions,
        metadata: undefined,
      })
      expect(authRequest.auth.userId).toBe(mockUser.id)
      expect(authRequest.auth.isAuth).toBe(true)
    })

    it('should NOT throw on invalid JWT (leaves user as null)', async () => {
      vi.mocked(jose.jwtVerify).mockRejectedValueOnce(new Error('Invalid JWT'))

      const request = createMockRequest({
        headers: { Authorization: 'Bearer invalid-jwt-token' },
      })

      const middleware = optionalAuth({ jwksUri: 'https://example.com/.well-known/jwks.json' })

      // Should not throw
      await expect(middleware(request)).resolves.not.toThrow()

      const authRequest = request as AuthRequest
      expect(authRequest.auth.user).toBeNull()
      expect(authRequest.auth.userId).toBeNull()
      expect(authRequest.auth.isAuth).toBe(false)
      // Token is still set even if verification fails
      expect(authRequest.auth.token).toBe('invalid-jwt-token')
    })

    it('should continue without error when no token present', async () => {
      const request = createMockRequest()

      const middleware = optionalAuth({ jwksUri: 'https://example.com/.well-known/jwks.json' })
      const result = await middleware(request)

      // Should return undefined (continue to next handler)
      expect(result).toBeUndefined()
    })

    it('should skip auth when skip function returns true', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: mockJwtPayload,
        protectedHeader: { alg: 'RS256' },
      } as any)

      const request = createMockRequest({
        url: 'https://example.com/public',
        headers: { Authorization: 'Bearer valid-token' },
      })

      const middleware = optionalAuth({
        jwksUri: 'https://example.com/.well-known/jwks.json',
        skip: (req) => req.url.includes('/public'),
      })
      await middleware(request)

      const authRequest = request as AuthRequest
      expect(authRequest.auth.user).toBeNull()
      expect(authRequest.auth.isAuth).toBe(false)
      expect(vi.mocked(jose.jwtVerify)).not.toHaveBeenCalled()
    })

    it('should use default WorkOS client ID', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: mockJwtPayload,
        protectedHeader: { alg: 'RS256' },
      } as any)

      const request = createMockRequest({
        headers: { Authorization: 'Bearer valid-token' },
      })

      // Not specifying clientId - should use default
      const middleware = optionalAuth({ jwksUri: 'https://example.com/.well-known/jwks.json' })
      await middleware(request)

      // Verify jwtVerify was called with correct audience (default client ID)
      expect(vi.mocked(jose.jwtVerify)).toHaveBeenCalled()
      const callArgs = vi.mocked(jose.jwtVerify).mock.calls[0]
      expect(callArgs[0]).toBe('valid-token')
      expect(callArgs[2]).toEqual({ audience: 'client_01JQYTRXK9ZPD8JPJTKDCRB656' })
    })

    it('should use custom client ID when provided', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: mockJwtPayload,
        protectedHeader: { alg: 'RS256' },
      } as any)

      const request = createMockRequest({
        headers: { Authorization: 'Bearer valid-token' },
      })

      const middleware = optionalAuth({
        clientId: 'custom_client_id',
        jwksUri: 'https://example.com/.well-known/jwks.json',
      })
      await middleware(request)

      // Verify jwtVerify was called with custom audience
      expect(vi.mocked(jose.jwtVerify)).toHaveBeenCalled()
      const callArgs = vi.mocked(jose.jwtVerify).mock.calls[0]
      expect(callArgs[0]).toBe('valid-token')
      expect(callArgs[2]).toEqual({ audience: 'custom_client_id' })
    })

    it('should handle JWT payload with minimal data', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: {
          sub: 'minimal_user',
          // No email, name, org_id, roles, permissions
        },
        protectedHeader: { alg: 'RS256' },
      } as any)

      const request = createMockRequest({
        headers: { Authorization: 'Bearer minimal-token' },
      })

      const middleware = optionalAuth({ jwksUri: 'https://example.com/.well-known/jwks.json' })
      await middleware(request)

      const authRequest = request as AuthRequest
      expect(authRequest.auth.user).toEqual({
        id: 'minimal_user',
        email: undefined,
        name: undefined,
        organizationId: undefined,
        roles: undefined,
        permissions: undefined,
        metadata: undefined,
      })
      expect(authRequest.auth.isAuth).toBe(true)
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // requireAuth middleware tests
  // ═══════════════════════════════════════════════════════════════════════════

  describe('requireAuth() middleware', () => {
    it('should return 401 when not authenticated', async () => {
      const request = createMockRequest()

      const middleware = requireAuth({ jwksUri: 'https://example.com/.well-known/jwks.json' })
      const response = await middleware(request)

      expect(response).toBeInstanceOf(Response)
      expect(response?.status).toBe(401)
      const data = await response?.json()
      expect(data.error).toBe('Authentication required')
    })

    it('should return 401 for invalid token', async () => {
      vi.mocked(jose.jwtVerify).mockRejectedValueOnce(new Error('Invalid JWT'))

      const request = createMockRequest({
        headers: { Authorization: 'Bearer invalid-token' },
      })

      const middleware = requireAuth({ jwksUri: 'https://example.com/.well-known/jwks.json' })
      const response = await middleware(request)

      expect(response?.status).toBe(401)
      const data = await response?.json()
      expect(data.error).toBe('Authentication required')
    })

    it('should return 401 for missing token', async () => {
      const request = createMockRequest()

      const middleware = requireAuth({ jwksUri: 'https://example.com/.well-known/jwks.json' })
      const response = await middleware(request)

      expect(response?.status).toBe(401)
    })

    it('should allow through when authenticated with valid token', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: mockJwtPayload,
        protectedHeader: { alg: 'RS256' },
      } as any)

      const request = createMockRequest({
        headers: { Authorization: 'Bearer valid-token' },
      })

      const middleware = requireAuth({ jwksUri: 'https://example.com/.well-known/jwks.json' })
      const response = await middleware(request)

      // Should return undefined (continue to next handler)
      expect(response).toBeUndefined()
      expect((request as AuthRequest).auth.isAuth).toBe(true)
    })

    it('should redirect when redirectTo option is set', async () => {
      const request = createMockRequest()

      const middleware = requireAuth({
        redirectTo: 'https://example.com/login', // Must be absolute URL for Response.redirect
        jwksUri: 'https://example.com/.well-known/jwks.json',
      })
      const response = await middleware(request)

      expect(response?.status).toBe(302)
      expect(response?.headers.get('Location')).toBe('https://example.com/login')
    })

    // Role-based access tests
    describe('role-based access', () => {
      it('should return 403 when missing required role', async () => {
        vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
          payload: {
            ...mockJwtPayload,
            roles: ['user'], // Only has 'user' role
          },
          protectedHeader: { alg: 'RS256' },
        } as any)

        const request = createMockRequest({
          headers: { Authorization: 'Bearer valid-token' },
        })

        const middleware = requireAuth({
          roles: ['admin', 'superadmin'],
          jwksUri: 'https://example.com/.well-known/jwks.json',
        })
        const response = await middleware(request)

        expect(response?.status).toBe(403)
        const data = await response?.json()
        expect(data.error).toBe('Insufficient permissions')
      })

      it('should allow any role from the list (OR logic)', async () => {
        vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
          payload: {
            ...mockJwtPayload,
            roles: ['moderator'], // Has 'moderator', not 'admin'
          },
          protectedHeader: { alg: 'RS256' },
        } as any)

        const request = createMockRequest({
          headers: { Authorization: 'Bearer valid-token' },
        })

        const middleware = requireAuth({
          roles: ['admin', 'moderator'],
          jwksUri: 'https://example.com/.well-known/jwks.json',
        })
        const response = await middleware(request)

        expect(response).toBeUndefined() // Allowed through
      })

      it('should allow through when user has one of required roles', async () => {
        vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
          payload: {
            ...mockJwtPayload,
            roles: ['admin', 'user'],
          },
          protectedHeader: { alg: 'RS256' },
        } as any)

        const request = createMockRequest({
          headers: { Authorization: 'Bearer valid-token' },
        })

        const middleware = requireAuth({
          roles: ['admin'],
          jwksUri: 'https://example.com/.well-known/jwks.json',
        })
        const response = await middleware(request)

        expect(response).toBeUndefined()
      })

      it('should handle user with no roles', async () => {
        vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
          payload: {
            sub: 'user_123',
            email: 'test@example.com',
            // No roles
          },
          protectedHeader: { alg: 'RS256' },
        } as any)

        const request = createMockRequest({
          headers: { Authorization: 'Bearer valid-token' },
        })

        const middleware = requireAuth({
          roles: ['admin'],
          jwksUri: 'https://example.com/.well-known/jwks.json',
        })
        const response = await middleware(request)

        expect(response?.status).toBe(403)
      })
    })

    // Permission-based access tests
    describe('permission-based access', () => {
      it('should return 403 when missing required permission', async () => {
        vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
          payload: {
            ...mockJwtPayload,
            permissions: ['read'], // Only has 'read' permission
          },
          protectedHeader: { alg: 'RS256' },
        } as any)

        const request = createMockRequest({
          headers: { Authorization: 'Bearer valid-token' },
        })

        const middleware = requireAuth({
          permissions: ['read', 'write'],
          jwksUri: 'https://example.com/.well-known/jwks.json',
        })
        const response = await middleware(request)

        expect(response?.status).toBe(403)
        const data = await response?.json()
        expect(data.error).toBe('Insufficient permissions')
      })

      it('should require all permissions (AND logic)', async () => {
        vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
          payload: {
            ...mockJwtPayload,
            permissions: ['read', 'delete'], // Missing 'write'
          },
          protectedHeader: { alg: 'RS256' },
        } as any)

        const request = createMockRequest({
          headers: { Authorization: 'Bearer valid-token' },
        })

        const middleware = requireAuth({
          permissions: ['read', 'write', 'delete'],
          jwksUri: 'https://example.com/.well-known/jwks.json',
        })
        const response = await middleware(request)

        expect(response?.status).toBe(403)
      })

      it('should allow through when user has all required permissions', async () => {
        vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
          payload: {
            ...mockJwtPayload,
            permissions: ['read', 'write', 'delete'],
          },
          protectedHeader: { alg: 'RS256' },
        } as any)

        const request = createMockRequest({
          headers: { Authorization: 'Bearer valid-token' },
        })

        const middleware = requireAuth({
          permissions: ['read', 'write'],
          jwksUri: 'https://example.com/.well-known/jwks.json',
        })
        const response = await middleware(request)

        expect(response).toBeUndefined()
      })

      it('should handle user with no permissions', async () => {
        vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
          payload: {
            sub: 'user_123',
            email: 'test@example.com',
            // No permissions
          },
          protectedHeader: { alg: 'RS256' },
        } as any)

        const request = createMockRequest({
          headers: { Authorization: 'Bearer valid-token' },
        })

        const middleware = requireAuth({
          permissions: ['read'],
          jwksUri: 'https://example.com/.well-known/jwks.json',
        })
        const response = await middleware(request)

        expect(response?.status).toBe(403)
      })
    })

    it('should run optionalAuth if auth not already initialized', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: mockJwtPayload,
        protectedHeader: { alg: 'RS256' },
      } as any)

      const request = createMockRequest({
        headers: { Authorization: 'Bearer valid-token' },
      })

      // Request does not have auth initialized
      expect((request as any).auth).toBeUndefined()

      const middleware = requireAuth({ jwksUri: 'https://example.com/.well-known/jwks.json' })
      await middleware(request)

      // Auth should now be initialized
      expect((request as AuthRequest).auth).toBeDefined()
      expect((request as AuthRequest).auth.isAuth).toBe(true)
    })

    it('should use existing auth context if already initialized', async () => {
      // Pre-initialize auth on request
      const request = createMockRequest({
        headers: { Authorization: 'Bearer already-verified-token' },
      })
      ;(request as AuthRequest).auth = {
        user: mockUser,
        userId: mockUser.id,
        isAuth: true,
        token: 'already-verified-token',
      }

      const middleware = requireAuth({ jwksUri: 'https://example.com/.well-known/jwks.json' })
      const response = await middleware(request)

      // Should not call jwtVerify again
      expect(vi.mocked(jose.jwtVerify)).not.toHaveBeenCalled()
      expect(response).toBeUndefined() // Allowed through
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // apiKey middleware tests
  // ═══════════════════════════════════════════════════════════════════════════

  describe('apiKey() middleware', () => {
    const mockVerify = vi.fn<(key: string, request: Request) => Promise<AuthUser | null>>()

    beforeEach(() => {
      mockVerify.mockReset()
    })

    it('should return 401 when no API key provided', async () => {
      const request = createMockRequest()

      const middleware = apiKey({ verify: mockVerify })
      const response = await middleware(request)

      expect(response).toBeInstanceOf(Response)
      expect(response?.status).toBe(401)
      const data = await response?.json()
      expect(data.error).toBe('API key required')
    })

    it('should return 401 for invalid API key', async () => {
      mockVerify.mockResolvedValueOnce(null)

      const request = createMockRequest({
        headers: { 'X-API-Key': 'invalid-key' },
      })

      const middleware = apiKey({ verify: mockVerify })
      const response = await middleware(request)

      expect(response?.status).toBe(401)
      const data = await response?.json()
      expect(data.error).toBe('Invalid API key')
      expect(mockVerify).toHaveBeenCalledWith('invalid-key', request)
    })

    it('should return 401 for missing API key', async () => {
      const request = createMockRequest()

      const middleware = apiKey({ verify: mockVerify })
      const response = await middleware(request)

      expect(response?.status).toBe(401)
      expect(mockVerify).not.toHaveBeenCalled()
    })

    it('should set user when valid API key', async () => {
      mockVerify.mockResolvedValueOnce(mockUser)

      const request = createMockRequest({
        headers: { 'X-API-Key': 'valid-api-key' },
      })

      const middleware = apiKey({ verify: mockVerify })
      const response = await middleware(request)

      // Should return undefined (continue to next handler)
      expect(response).toBeUndefined()

      const authRequest = request as AuthRequest
      expect(authRequest.auth.user).toEqual(mockUser)
      expect(authRequest.auth.userId).toBe(mockUser.id)
      expect(authRequest.auth.isAuth).toBe(true)
      expect(authRequest.auth.token).toBe('valid-api-key')
    })

    it('should use custom header name when specified', async () => {
      mockVerify.mockResolvedValueOnce(mockUser)

      const request = createMockRequest({
        headers: { Authorization: 'api_key_12345' },
      })

      const middleware = apiKey({
        headerName: 'Authorization',
        verify: mockVerify,
      })
      const response = await middleware(request)

      expect(response).toBeUndefined()
      expect(mockVerify).toHaveBeenCalledWith('api_key_12345', request)
    })

    it('should pass request to verify function', async () => {
      mockVerify.mockImplementation(async (key, req) => {
        // Verify that request is passed correctly
        if (req.url.includes('/api/data')) {
          return mockUser
        }
        return null
      })

      const request = createMockRequest({
        url: 'https://example.com/api/data',
        headers: { 'X-API-Key': 'valid-key' },
      })

      const middleware = apiKey({ verify: mockVerify })
      const response = await middleware(request)

      expect(response).toBeUndefined()
      expect(mockVerify).toHaveBeenCalledWith('valid-key', request)
    })

    it('should handle verify function that throws', async () => {
      mockVerify.mockRejectedValueOnce(new Error('Verify error'))

      const request = createMockRequest({
        headers: { 'X-API-Key': 'error-key' },
      })

      const middleware = apiKey({ verify: mockVerify })

      // Should propagate the error
      await expect(middleware(request)).rejects.toThrow('Verify error')
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // combined middleware tests
  // ═══════════════════════════════════════════════════════════════════════════

  describe('combined() middleware', () => {
    const mockApiKeyVerify = vi.fn<(key: string, request: Request) => Promise<AuthUser | null>>()

    beforeEach(() => {
      mockApiKeyVerify.mockReset()
    })

    it('should try JWT first, then API key fallback', async () => {
      // JWT fails
      vi.mocked(jose.jwtVerify).mockRejectedValueOnce(new Error('Invalid JWT'))
      // API key succeeds
      mockApiKeyVerify.mockResolvedValueOnce(mockUser)

      const request = createMockRequest({
        headers: {
          Authorization: 'Bearer invalid-jwt',
          'X-API-Key': 'valid-api-key',
        },
      })

      const middleware = combined({
        auth: { jwksUri: 'https://example.com/.well-known/jwks.json' },
        apiKey: { verify: mockApiKeyVerify },
      })
      const response = await middleware(request)

      expect(response).toBeUndefined()
      expect((request as AuthRequest).auth.isAuth).toBe(true)
      expect((request as AuthRequest).auth.token).toBe('valid-api-key')
    })

    it('should return 401 when both fail', async () => {
      // JWT fails
      vi.mocked(jose.jwtVerify).mockRejectedValueOnce(new Error('Invalid JWT'))
      // API key fails
      mockApiKeyVerify.mockResolvedValueOnce(null)

      const request = createMockRequest({
        headers: {
          Authorization: 'Bearer invalid-jwt',
          'X-API-Key': 'invalid-api-key',
        },
      })

      const middleware = combined({
        auth: { jwksUri: 'https://example.com/.well-known/jwks.json' },
        apiKey: { verify: mockApiKeyVerify },
      })
      const response = await middleware(request)

      expect(response?.status).toBe(401)
      const data = await response?.json()
      expect(data.error).toBe('Authentication required')
    })

    it('should prefer JWT (tried first)', async () => {
      // JWT succeeds
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: mockJwtPayload,
        protectedHeader: { alg: 'RS256' },
      } as any)
      mockApiKeyVerify.mockResolvedValueOnce(mockUser)

      const request = createMockRequest({
        headers: {
          Authorization: 'Bearer valid-jwt',
          'X-API-Key': 'valid-api-key',
        },
      })

      const middleware = combined({
        auth: { jwksUri: 'https://example.com/.well-known/jwks.json' },
        apiKey: { verify: mockApiKeyVerify },
      })
      await middleware(request)

      // Should use JWT, not API key
      expect(vi.mocked(jose.jwtVerify)).toHaveBeenCalled()
      expect(mockApiKeyVerify).not.toHaveBeenCalled()
      expect((request as AuthRequest).auth.token).toBe('valid-jwt')
    })

    it('should return 401 when no auth provided', async () => {
      const request = createMockRequest()

      const middleware = combined({
        auth: { jwksUri: 'https://example.com/.well-known/jwks.json' },
        apiKey: { verify: mockApiKeyVerify },
      })
      const response = await middleware(request)

      expect(response?.status).toBe(401)
    })

    it('should work with only JWT auth configured', async () => {
      vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
        payload: mockJwtPayload,
        protectedHeader: { alg: 'RS256' },
      } as any)

      const request = createMockRequest({
        headers: { Authorization: 'Bearer valid-jwt' },
      })

      const middleware = combined({
        auth: { jwksUri: 'https://example.com/.well-known/jwks.json' },
        // No apiKey configured
      })
      const response = await middleware(request)

      expect(response).toBeUndefined()
      expect((request as AuthRequest).auth.isAuth).toBe(true)
    })

    it('should work with only API key configured', async () => {
      mockApiKeyVerify.mockResolvedValueOnce(mockUser)

      const request = createMockRequest({
        headers: { 'X-API-Key': 'valid-api-key' },
      })

      const middleware = combined({
        // No auth (JWT) configured
        apiKey: { verify: mockApiKeyVerify },
      })
      const response = await middleware(request)

      expect(response).toBeUndefined()
      expect((request as AuthRequest).auth.isAuth).toBe(true)
    })

    it('should fall back to API key when JWT not present', async () => {
      mockApiKeyVerify.mockResolvedValueOnce(mockUser)

      const request = createMockRequest({
        headers: { 'X-API-Key': 'valid-api-key' },
        // No Authorization header
      })

      const middleware = combined({
        auth: { jwksUri: 'https://example.com/.well-known/jwks.json' },
        apiKey: { verify: mockApiKeyVerify },
      })
      const response = await middleware(request)

      expect(response).toBeUndefined()
      expect((request as AuthRequest).auth.isAuth).toBe(true)
      expect((request as AuthRequest).auth.token).toBe('valid-api-key')
    })

    it('should use custom API key header name', async () => {
      mockApiKeyVerify.mockResolvedValueOnce(mockUser)

      const request = createMockRequest({
        headers: { 'Custom-API-Header': 'custom-api-key' },
      })

      const middleware = combined({
        apiKey: {
          headerName: 'Custom-API-Header',
          verify: mockApiKeyVerify,
        },
      })
      const response = await middleware(request)

      expect(response).toBeUndefined()
      expect(mockApiKeyVerify).toHaveBeenCalledWith('custom-api-key', request)
    })

    it('should initialize auth context if not already set', async () => {
      mockApiKeyVerify.mockResolvedValueOnce(mockUser)

      const request = createMockRequest({
        headers: { 'X-API-Key': 'valid-api-key' },
      })

      // Simulate scenario where auth not set by JWT (no auth option provided)
      const middleware = combined({
        apiKey: { verify: mockApiKeyVerify },
      })
      await middleware(request)

      // Auth should be initialized
      expect((request as AuthRequest).auth).toBeDefined()
      expect((request as AuthRequest).auth.isAuth).toBe(true)
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // Utility exports tests
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Utility exports', () => {
    describe('getAuth()', () => {
      it('should return auth context from request', async () => {
        vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
          payload: mockJwtPayload,
          protectedHeader: { alg: 'RS256' },
        } as any)

        const request = createMockRequest({
          headers: { Authorization: 'Bearer valid-token' },
        })

        const middleware = optionalAuth({ jwksUri: 'https://example.com/.well-known/jwks.json' })
        await middleware(request)

        const auth = getAuth(request)
        expect(auth.isAuth).toBe(true)
        expect(auth.user?.id).toBe(mockUser.id)
      })

      it('should return default context when auth not initialized', () => {
        const request = createMockRequest()

        const auth = getAuth(request)
        expect(auth.user).toBeNull()
        expect(auth.userId).toBeNull()
        expect(auth.isAuth).toBe(false)
        expect(auth.token).toBeNull()
      })
    })

    describe('isAuthenticated()', () => {
      it('should return true when authenticated', async () => {
        vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
          payload: mockJwtPayload,
          protectedHeader: { alg: 'RS256' },
        } as any)

        const request = createMockRequest({
          headers: { Authorization: 'Bearer valid-token' },
        })

        const middleware = optionalAuth({ jwksUri: 'https://example.com/.well-known/jwks.json' })
        await middleware(request)

        expect(isAuthenticated(request)).toBe(true)
      })

      it('should return false when not authenticated', () => {
        const request = createMockRequest()

        expect(isAuthenticated(request)).toBe(false)
      })
    })

    describe('getUser()', () => {
      it('should return user when authenticated', async () => {
        vi.mocked(jose.jwtVerify).mockResolvedValueOnce({
          payload: mockJwtPayload,
          protectedHeader: { alg: 'RS256' },
        } as any)

        const request = createMockRequest({
          headers: { Authorization: 'Bearer valid-token' },
        })

        const middleware = optionalAuth({ jwksUri: 'https://example.com/.well-known/jwks.json' })
        await middleware(request)

        const user = getUser(request)
        expect(user?.id).toBe(mockUser.id)
        expect(user?.email).toBe(mockUser.email)
      })

      it('should return null when not authenticated', () => {
        const request = createMockRequest()

        expect(getUser(request)).toBeNull()
      })
    })
  })
})
