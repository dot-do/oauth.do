import { defineWorkersConfig } from '@cloudflare/vitest-pool-workers/config'

export default defineWorkersConfig({
  test: {
    include: ['test-integration/**/*.test.ts'],
    testTimeout: 30_000,
    hookTimeout: 30_000,
    poolOptions: {
      workers: {
        singleWorker: true,
        // Use test config — same as wrangler.jsonc but without the OAUTH
        // service binding that miniflare can't resolve locally.
        // The auth worker gracefully falls back to direct WorkOS API calls.
        wrangler: { configPath: './wrangler.test.jsonc' },
      },
    },
  },
})
