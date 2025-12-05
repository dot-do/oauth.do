import { defineConfig } from 'tsup'

export default defineConfig({
	entry: ['src/index.ts', 'src/cli.ts'],
	format: ['esm'],
	dts: {
		entry: ['src/index.ts'],
	},
	splitting: false,
	sourcemap: true,
	clean: true,
	treeshake: true,
	minify: false,
	outDir: 'dist',
	// Don't bundle native modules or heavy dependencies - they must be required at runtime
	external: ['keytar', 'open'],
})
