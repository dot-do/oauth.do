import { defineConfig } from 'vitest/config'
import { resolve } from 'path'

export default defineConfig({
	test: {
		globals: true,
		environment: 'jsdom',
		include: ['tests/**/*.test.ts', 'tests/**/*.test.tsx', 'core/src/**/*.test.ts', 'workers/**/*.test.ts'],
		setupFiles: [resolve(__dirname, 'tests/setup.ts')],
		pool: 'forks',
		poolOptions: {
			forks: {
				singleFork: true,
			},
		},
		maxConcurrency: 1,
		fileParallelism: false,
		coverage: {
			provider: 'v8',
			reporter: ['text', 'json', 'html'],
			exclude: ['dist', 'node_modules', 'tests'],
			thresholds: {
				lines: 70,
				branches: 60,
				functions: 70,
				statements: 70,
			},
		},
	},
	resolve: {
		alias: {
			// Mock cloudflare:workers for Node.js tests
			'cloudflare:workers': resolve(__dirname, 'tests/mocks/cloudflare-workers.ts'),
			// Mock @mdxui/auth for React tests (package has broken dependencies)
			'@mdxui/auth': resolve(__dirname, 'tests/mocks/mdxui-auth.ts'),
		},
	},
})
