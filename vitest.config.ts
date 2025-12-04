import { defineConfig } from 'vitest/config'

export default defineConfig({
	test: {
		globals: true,
		environment: 'jsdom',
		include: ['tests/**/*.test.ts', 'tests/**/*.test.tsx'],
		setupFiles: ['./tests/setup.ts'],
		coverage: {
			provider: 'v8',
			reporter: ['text', 'json', 'html'],
			exclude: ['dist', 'node_modules', 'tests'],
		},
	},
})
