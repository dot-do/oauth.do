import { defineConfig } from 'tsup'

export default defineConfig({
	entry: [
		'src/index.ts',
		'src/node.ts',
		'src/cli.ts',
		'src/react.tsx',
		'src/hono.ts',
		'src/itty.ts',
		'src/session.ts',
		'src/session-hono.ts',
		'src/types-export.ts',
		'src/rpc.ts',
	],
	format: ['esm'],
	dts: {
		entry: ['src/index.ts', 'src/node.ts', 'src/react.tsx', 'src/hono.ts', 'src/itty.ts', 'src/session.ts', 'src/session-hono.ts', 'src/types-export.ts', 'src/rpc.ts'],
	},
	splitting: false,
	sourcemap: true,
	clean: true,
	treeshake: true,
	minify: false,
	outDir: 'dist',
	// Don't bundle these - they must be required at runtime
	external: [
		'keytar',
		'open',
		'react',
		'react-dom',
		'hono',
		'jose',
		'@mdxui/auth',
		'@radix-ui/themes',
		'@tanstack/react-query',
	],
	esbuildOptions(options) {
		// For React JSX
		options.jsx = 'automatic'
	},
})
