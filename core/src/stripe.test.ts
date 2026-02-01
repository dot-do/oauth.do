import { describe, it, expect, vi, beforeEach } from 'vitest'
import {
  createStripeClient,
  verifyStripeWebhookAsync,
  computeStripeSignature,
  timingSafeEqual,
} from './stripe.js'

const TEST_SECRET = 'whsec_test_secret_key'
const TEST_PAYLOAD = JSON.stringify({
  id: 'evt_123',
  type: 'customer.created',
  data: { object: { id: 'cus_123' } },
})

async function makeSignatureHeader(
  payload: string,
  secret: string,
  timestampOverride?: number
): Promise<string> {
  const timestamp = timestampOverride ?? Math.floor(Date.now() / 1000)
  const sig = await computeStripeSignature(timestamp, payload, secret)
  return `t=${timestamp},v1=${sig}`
}

describe('constructEvent', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('correctly verifies valid webhook signatures', async () => {
    const client = createStripeClient('sk_test_123')
    const sig = await makeSignatureHeader(TEST_PAYLOAD, TEST_SECRET)

    const event = await client.webhooks.constructEvent(TEST_PAYLOAD, sig, TEST_SECRET)
    expect(event.id).toBe('evt_123')
    expect(event.type).toBe('customer.created')
  })

  it('rejects invalid signatures', async () => {
    const client = createStripeClient('sk_test_123')
    const sig = await makeSignatureHeader(TEST_PAYLOAD, 'whsec_wrong_secret')

    await expect(
      client.webhooks.constructEvent(TEST_PAYLOAD, sig, TEST_SECRET)
    ).rejects.toThrow('Invalid webhook signature')
  })

  it('rejects expired timestamps (beyond tolerance)', async () => {
    const client = createStripeClient('sk_test_123')
    const oldTimestamp = Math.floor(Date.now() / 1000) - 400 // 6+ minutes ago
    const sig = await makeSignatureHeader(TEST_PAYLOAD, TEST_SECRET, oldTimestamp)

    await expect(
      client.webhooks.constructEvent(TEST_PAYLOAD, sig, TEST_SECRET)
    ).rejects.toThrow('Webhook timestamp too old')
  })

  it('accepts timestamps within tolerance', async () => {
    const client = createStripeClient('sk_test_123')
    const recentTimestamp = Math.floor(Date.now() / 1000) - 60 // 1 minute ago
    const sig = await makeSignatureHeader(TEST_PAYLOAD, TEST_SECRET, recentTimestamp)

    const event = await client.webhooks.constructEvent(TEST_PAYLOAD, sig, TEST_SECRET)
    expect(event.id).toBe('evt_123')
  })
})

describe('verifyStripeWebhookAsync', () => {
  it('verifies valid signatures', async () => {
    const sig = await makeSignatureHeader(TEST_PAYLOAD, TEST_SECRET)
    const event = await verifyStripeWebhookAsync(TEST_PAYLOAD, sig, TEST_SECRET)
    expect(event.id).toBe('evt_123')
  })

  it('rejects invalid signatures', async () => {
    const sig = await makeSignatureHeader(TEST_PAYLOAD, 'whsec_wrong')
    await expect(
      verifyStripeWebhookAsync(TEST_PAYLOAD, sig, TEST_SECRET)
    ).rejects.toThrow('Invalid webhook signature')
  })
})

describe('createStripeCustomer', () => {
  it('makes correct API call', async () => {
    const mockResponse = { id: 'cus_new123' }
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      })
    )

    const client = createStripeClient('sk_test_key')
    const result = await client.customers.create({
      email: 'test@example.com',
      name: 'Test User',
      metadata: { userId: 'u_1' },
    })

    expect(result.id).toBe('cus_new123')
    const fetchCall = (fetch as ReturnType<typeof vi.fn>).mock.calls[0]
    expect(fetchCall[0]).toBe('https://api.stripe.com/v1/customers')
    expect(fetchCall[1].method).toBe('POST')
    expect(fetchCall[1].headers.Authorization).toBe('Bearer sk_test_key')
    expect(fetchCall[1].body).toContain('email=test%40example.com')

    vi.unstubAllGlobals()
  })
})

describe('timingSafeEqual', () => {
  it('returns true for equal strings', () => {
    expect(timingSafeEqual('abc', 'abc')).toBe(true)
    expect(timingSafeEqual('', '')).toBe(true)
  })

  it('returns false for different strings', () => {
    expect(timingSafeEqual('abc', 'abd')).toBe(false)
    expect(timingSafeEqual('abc', 'xyz')).toBe(false)
  })

  it('returns false for different length strings without leaking length', () => {
    // The function should handle different lengths without early return
    expect(timingSafeEqual('abc', 'abcd')).toBe(false)
    expect(timingSafeEqual('a', 'ab')).toBe(false)
    expect(timingSafeEqual('short', 'muchlongerstring')).toBe(false)
  })
})
