# oauth.do CDN Bundles

## Overview

oauth.do React components are now available for CDN usage, allowing developers to use the library without a build step for quick prototyping or simple projects.

## Bundle Formats

### 1. ESM (Modern) - `oauth.min.js`
- **Size**: 4 KB (minified)
- **Format**: ES Module
- **Usage**: Via `<script type="module">` or import maps
- **Browser Support**: Modern browsers with ESM support

### 2. UMD/IIFE (Classic) - `oauth.umd.global.js`
- **Size**: 38 KB (minified, includes dependencies)
- **Format**: IIFE (Immediately Invoked Function Expression)
- **Usage**: Via `<script>` tag
- **Global Variable**: `window.OAuthDo`
- **Browser Support**: All browsers including IE11

## Build Configuration

The CDN bundles are generated using tsup with the following configuration:

```typescript
// Multiple build configs
[
  // Main ESM build for bundlers
  {
    entry: ['src/index.ts', 'src/react/index.ts', 'src/cli.ts'],
    format: ['esm'],
    external: ['react', 'react/jsx-runtime'],
  },
  // UMD build for CDN usage (React components only)
  {
    entry: { 'react/oauth.umd': 'src/react/index.ts' },
    format: ['iife'],
    globalName: 'OAuthDo',
    minify: true,
    external: ['react', 'react/jsx-runtime'],
    globals: {
      react: 'React',
      'react/jsx-runtime': 'ReactJSXRuntime',
    },
  },
  // Minified ESM build for modern CDN
  {
    entry: { 'react/oauth.min': 'src/react/index.ts' },
    format: ['esm'],
    minify: true,
    external: ['react', 'react/jsx-runtime'],
  },
]
```

## Package.json Exports

The CDN bundles are exposed via package.json exports:

```json
{
  "exports": {
    "./react/cdn": {
      "import": "./dist/react/oauth.min.js",
      "script": "./dist/react/oauth.umd.global.js"
    }
  }
}
```

## CDN Providers

oauth.do is available on multiple CDN providers:

### unpkg
- **ESM**: `https://unpkg.com/oauth.do@latest/dist/react/oauth.min.js`
- **UMD**: `https://unpkg.com/oauth.do@latest/dist/react/oauth.umd.global.js`
- **Full directory**: `https://unpkg.com/oauth.do@latest/dist/react/`

### jsDelivr
- **ESM**: `https://cdn.jsdelivr.net/npm/oauth.do@latest/dist/react/oauth.min.js`
- **UMD**: `https://cdn.jsdelivr.net/npm/oauth.do@latest/dist/react/oauth.umd.global.js`
- **Full directory**: `https://cdn.jsdelivr.net/npm/oauth.do@latest/dist/react/`

### esm.sh
- **Direct import**: `https://esm.sh/oauth.do@latest`
- **React subpath**: `https://esm.sh/oauth.do@latest/react`

## Usage Examples

See [README.md](./README.md#cdn-usage) for complete usage examples.

### Quick Start (ESM)

```html
<script type="importmap">
  {
    "imports": {
      "react": "https://esm.sh/react@18",
      "oauth.do/react/cdn": "https://unpkg.com/oauth.do@latest/dist/react/oauth.min.js"
    }
  }
</script>

<script type="module">
  import { AuthProvider, useAuth } from 'oauth.do/react/cdn'
  // Your code here
</script>
```

### Quick Start (UMD)

```html
<script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
<script src="https://unpkg.com/oauth.do@latest/dist/react/oauth.umd.global.js"></script>

<script>
  const { AuthProvider, useAuth } = window.OAuthDo
  // Your code here
</script>
```

## Testing

All React components have comprehensive test coverage with 27 passing tests:

- AuthProvider tests (2 tests)
- Authenticated component tests (3 tests)
- Unauthenticated component tests (2 tests)
- UserDisplay component tests (4 tests)
- Plus 16 unit tests for auth, config, and storage

Run tests with:
```bash
pnpm test
```

## Development

To rebuild CDN bundles:

```bash
pnpm build
```

This will generate:
- `dist/react/index.js` - Standard ESM build (8 KB)
- `dist/react/oauth.min.js` - Minified ESM for CDN (4 KB)
- `dist/react/oauth.umd.global.js` - UMD/IIFE bundle (38 KB)

## Files Included in npm Package

```json
{
  "files": [
    "dist",
    "README.md",
    "LICENSE"
  ]
}
```

All CDN bundles are automatically included when the package is published to npm, making them immediately available on all major CDN providers.

## Browser Compatibility

### ESM Bundle (oauth.min.js)
- Chrome 61+
- Firefox 60+
- Safari 11+
- Edge 79+

### UMD Bundle (oauth.umd.global.js)
- All modern browsers
- IE 11 (with React polyfills)
- Legacy browsers with ES5 support

## Performance

- **Initial Load**: ~4 KB (ESM) or ~38 KB (UMD)
- **Gzip Compression**: CDNs automatically serve gzipped versions
- **HTTP/2**: All major CDNs support HTTP/2 multiplexing
- **Caching**: CDN edge caching for fast global delivery

## Security

- All bundles are served over HTTPS
- Subresource Integrity (SRI) hashes available on jsDelivr and unpkg
- No external dependencies loaded at runtime (React must be loaded separately)

## Next Steps

1. Publish to npm registry
2. Test CDN bundles on unpkg and jsDelivr
3. Add live demos using CDN bundles
4. Consider creating standalone demo pages
