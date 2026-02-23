import { describe, it, expect } from 'vitest'
import {
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
} from 'id.org.ai/oauth'

describe('PKCE', () => {
  describe('generateCodeVerifier', () => {
    it('generates verifier of correct length', () => {
      const verifier = generateCodeVerifier(64)
      expect(verifier).toHaveLength(64)
    })

    it('generates verifier with default length', () => {
      const verifier = generateCodeVerifier()
      expect(verifier).toHaveLength(64)
    })

    it('throws for invalid length', () => {
      expect(() => generateCodeVerifier(42)).toThrow('between 43 and 128')
      expect(() => generateCodeVerifier(129)).toThrow('between 43 and 128')
    })

    it('uses only allowed characters', () => {
      const verifier = generateCodeVerifier(128)
      expect(verifier).toMatch(/^[A-Za-z0-9\-._~]+$/)
    })

    it('generates unique values', () => {
      const v1 = generateCodeVerifier()
      const v2 = generateCodeVerifier()
      expect(v1).not.toBe(v2)
    })
  })

  describe('generateCodeChallenge', () => {
    it('generates base64url encoded challenge', async () => {
      const verifier = 'test-verifier-string-with-enough-characters-to-be-valid'
      const challenge = await generateCodeChallenge(verifier)
      // Base64URL should not have +, /, or =
      expect(challenge).not.toMatch(/[+/=]/)
    })

    it('produces consistent output for same input', async () => {
      const verifier = 'consistent-test-verifier'
      const c1 = await generateCodeChallenge(verifier)
      const c2 = await generateCodeChallenge(verifier)
      expect(c1).toBe(c2)
    })
  })

  describe('verifyCodeChallenge', () => {
    it('verifies valid challenge', async () => {
      const verifier = generateCodeVerifier()
      const challenge = await generateCodeChallenge(verifier)
      const valid = await verifyCodeChallenge(verifier, challenge, 'S256')
      expect(valid).toBe(true)
    })

    it('rejects invalid verifier', async () => {
      const verifier = generateCodeVerifier()
      const challenge = await generateCodeChallenge(verifier)
      const valid = await verifyCodeChallenge('wrong-verifier', challenge, 'S256')
      expect(valid).toBe(false)
    })

    it('rejects non-S256 method', async () => {
      const verifier = generateCodeVerifier()
      const challenge = await generateCodeChallenge(verifier)
      const valid = await verifyCodeChallenge(verifier, challenge, 'plain')
      expect(valid).toBe(false)
    })
  })

  describe('generatePkce', () => {
    it('generates valid PKCE pair', async () => {
      const { verifier, challenge } = await generatePkce()
      expect(verifier).toHaveLength(64)
      expect(challenge).toBeTruthy()
      const valid = await verifyCodeChallenge(verifier, challenge, 'S256')
      expect(valid).toBe(true)
    })
  })
})

describe('Token Generation', () => {
  describe('generateState', () => {
    it('generates state of correct length', () => {
      const state = generateState(32)
      expect(state).toHaveLength(32)
    })

    it('generates unique values', () => {
      const s1 = generateState()
      const s2 = generateState()
      expect(s1).not.toBe(s2)
    })
  })

  describe('generateToken', () => {
    it('generates token of correct length', () => {
      const token = generateToken(48)
      expect(token).toHaveLength(48)
    })

    it('generates unique values', () => {
      const t1 = generateToken()
      const t2 = generateToken()
      expect(t1).not.toBe(t2)
    })
  })

  describe('generateAuthorizationCode', () => {
    it('generates 48-character code', () => {
      const code = generateAuthorizationCode()
      expect(code).toHaveLength(48)
    })
  })
})

describe('Client Secret', () => {
  describe('hashClientSecret', () => {
    it('produces consistent hash', async () => {
      const secret = 'my-client-secret'
      const h1 = await hashClientSecret(secret)
      const h2 = await hashClientSecret(secret)
      expect(h1).toBe(h2)
    })

    it('produces different hash for different secrets', async () => {
      const h1 = await hashClientSecret('secret1')
      const h2 = await hashClientSecret('secret2')
      expect(h1).not.toBe(h2)
    })
  })

  describe('verifyClientSecret', () => {
    it('verifies valid secret', async () => {
      const secret = 'my-client-secret'
      const hash = await hashClientSecret(secret)
      const valid = await verifyClientSecret(secret, hash)
      expect(valid).toBe(true)
    })

    it('rejects invalid secret', async () => {
      const hash = await hashClientSecret('correct-secret')
      const valid = await verifyClientSecret('wrong-secret', hash)
      expect(valid).toBe(false)
    })
  })
})

describe('Base64URL', () => {
  describe('base64UrlEncode/Decode', () => {
    it('round-trips binary data', () => {
      const original = new Uint8Array([0, 1, 2, 255, 254, 253])
      const encoded = base64UrlEncode(original.buffer)
      const decoded = base64UrlDecode(encoded)
      expect(new Uint8Array(decoded)).toEqual(original)
    })

    it('does not use standard base64 chars', () => {
      // Create data that would produce + and / in standard base64
      const data = new Uint8Array([251, 239, 190])
      const encoded = base64UrlEncode(data.buffer)
      expect(encoded).not.toContain('+')
      expect(encoded).not.toContain('/')
    })
  })
})

describe('constantTimeEqual', () => {
  it('returns true for equal strings', async () => {
    expect(await constantTimeEqual('abc', 'abc')).toBe(true)
    expect(await constantTimeEqual('', '')).toBe(true)
  })

  it('returns false for different strings', async () => {
    expect(await constantTimeEqual('abc', 'abd')).toBe(false)
    expect(await constantTimeEqual('abc', 'ab')).toBe(false)
    expect(await constantTimeEqual('abc', 'abcd')).toBe(false)
  })

  it('has constant-time behavior regardless of string length differences', async () => {
    // This test verifies that comparing strings of different lengths
    // takes approximately the same time as comparing strings of the same length.
    // The hash-based approach ensures this by always comparing fixed-length hashes.

    const iterations = 100
    const baseString = 'a'.repeat(100)

    // Measure time for same-length comparison (mismatch at end)
    const sameLengthStart = performance.now()
    for (let i = 0; i < iterations; i++) {
      await constantTimeEqual(baseString, baseString.slice(0, -1) + 'b')
    }
    const sameLengthTime = performance.now() - sameLengthStart

    // Measure time for different-length comparison (short vs long)
    const diffLengthStart = performance.now()
    for (let i = 0; i < iterations; i++) {
      await constantTimeEqual('a', baseString)
    }
    const diffLengthTime = performance.now() - diffLengthStart

    // Measure time for different-length comparison (long vs short)
    const diffLengthStart2 = performance.now()
    for (let i = 0; i < iterations; i++) {
      await constantTimeEqual(baseString, 'a')
    }
    const diffLengthTime2 = performance.now() - diffLengthStart2

    // The times should be within reasonable variance of each other
    // We use a generous tolerance (5x) to account for system variance
    // The key is that different-length comparisons don't return instantly
    const avgDiffLengthTime = (diffLengthTime + diffLengthTime2) / 2
    const ratio = Math.max(sameLengthTime, avgDiffLengthTime) /
                  Math.min(sameLengthTime, avgDiffLengthTime)

    // Ratio should be less than 5x - if early return existed, it would be much faster
    expect(ratio).toBeLessThan(5)
  })

  it('correctly compares strings of vastly different lengths', async () => {
    // Ensure correctness is maintained for different lengths
    expect(await constantTimeEqual('short', 'a very long string that is much longer')).toBe(false)
    expect(await constantTimeEqual('a very long string that is much longer', 'short')).toBe(false)
    expect(await constantTimeEqual('x', 'x')).toBe(true)
    expect(await constantTimeEqual('x', 'y')).toBe(false)
  })
})
