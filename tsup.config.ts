import { defineConfig } from 'tsup'

export default defineConfig([
	// Main ESM build for bundlers
	{
		entry: ['src/index.ts', 'src/react/index.ts', 'src/cli.ts'],
		format: ['esm'],
		dts: {
			entry: ['src/index.ts', 'src/react/index.ts'],
		},
		splitting: false,
		sourcemap: true,
		clean: true,
		treeshake: true,
		minify: false,
		external: ['react', 'react/jsx-runtime'],
		outDir: 'dist',
	},
	// UMD build for CDN usage (React components only)
	{
		entry: {
			'react/oauth.umd': 'src/react/index.ts',
		},
		format: ['iife'],
		globalName: 'OAuthDo',
		minify: true,
		sourcemap: true,
		external: ['react', 'react/jsx-runtime'],
		outDir: 'dist',
		// React will be available as global React
		globals: {
			react: 'React',
			'react/jsx-runtime': 'ReactJSXRuntime',
		},
		esbuildOptions(options) {
			options.banner = {
				js: '/* oauth.do React Components - CDN Bundle */',
			}
		},
	},
	// Minified ESM build for modern CDN
	{
		entry: {
			'react/oauth.min': 'src/react/index.ts',
		},
		format: ['esm'],
		minify: true,
		sourcemap: true,
		external: ['react', 'react/jsx-runtime'],
		outDir: 'dist',
	},
])
