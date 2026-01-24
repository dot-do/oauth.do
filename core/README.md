# @dotdo/oauth

OAuth 2.1 authorization server for MCP (Model Context Protocol) compatibility.

## The Problem

You're building an MCP server. Claude and ChatGPT need to authenticate. But OAuth 2.1 is new, the docs are scattered, and you've spent hours debugging `.well-known` endpoints and CORS headers.

## The Solution

```typescript
import { createOAuth21Server, MemoryOAuthStorage } from '@dotdo/oauth'

const oauth = createOAuth21Server({
  issuer: 'https://your-mcp.do',
  storage: new MemoryOAuthStorage(),
  upstream: {
    provider: 'workos',
    apiKey: process.env.WORKOS_API_KEY,
    clientId: process.env.WORKOS_CLIENT_ID,
  },
})

// Mount it. Done.
app.route('/', oauth)
```

Your MCP server now speaks OAuth 2.1. Claude can connect.

## What This Does

This package creates a **federated OAuth 2.1 server**:

- It's an OAuth **SERVER** to MCP clients (Claude, ChatGPT)
- It's an OAuth **CLIENT** to your identity provider (WorkOS, Auth0)

```
┌─────────────────┐      ┌──────────────────┐      ┌─────────────┐
│  Claude/ChatGPT │ ───> │  Your MCP Server │ ───> │   WorkOS    │
│  (OAuth Client) │      │ (OAuth Server +  │      │  (Upstream) │
│                 │ <─── │   OAuth Client)  │ <─── │             │
└─────────────────┘      └──────────────────┘      └─────────────┘
```

## Endpoints

Once mounted, your server provides:

| Endpoint | Purpose |
|----------|---------|
| `/.well-known/oauth-authorization-server` | Server metadata (RFC 8414) |
| `/.well-known/oauth-protected-resource` | Resource metadata |
| `/authorize` | Authorization endpoint |
| `/token` | Token endpoint |
| `/register` | Dynamic client registration |
| `/revoke` | Token revocation |

## Features

- **OAuth 2.1 compliant** - PKCE required, S256 only
- **MCP compatible** - Works with Claude, ChatGPT, and other MCP clients
- **Federated auth** - Delegates to WorkOS, Auth0, or custom providers
- **Storage agnostic** - Bring your own storage backend
- **Zero dependencies** on `oauth.do` or `@dotdo/do` - this is the leaf package

## Storage

The package provides `MemoryOAuthStorage` for testing. For production, implement the `OAuthStorage` interface:

```typescript
import type { OAuthStorage } from '@dotdo/oauth'

class MyStorage implements OAuthStorage {
  async getUser(id: string) { /* ... */ }
  async saveUser(user: OAuthUser) { /* ... */ }
  async getClient(clientId: string) { /* ... */ }
  // ... other methods
}
```

If you're using `@dotdo/do`, it provides `DOAuthStorage` that implements this interface using Durable Object SQLite storage.

## Configuration

```typescript
createOAuth21Server({
  // Required
  issuer: 'https://your-domain.com',      // Your server's URL
  storage: new MemoryOAuthStorage(),       // Storage backend
  upstream: {                              // Identity provider
    provider: 'workos',
    apiKey: 'sk_...',
    clientId: 'client_...',
  },

  // Optional
  scopes: ['openid', 'profile', 'email'],  // Supported scopes
  accessTokenTtl: 3600,                    // 1 hour (default)
  refreshTokenTtl: 2592000,                // 30 days (default)
  authCodeTtl: 600,                        // 10 minutes (default)
  enableDynamicRegistration: true,         // Allow client registration
  debug: false,                            // Debug logging

  // Callbacks
  onUserAuthenticated: async (user) => {
    console.log('User logged in:', user.email)
  },
})
```

## Upstream Providers

### WorkOS

```typescript
upstream: {
  provider: 'workos',
  apiKey: process.env.WORKOS_API_KEY,
  clientId: process.env.WORKOS_CLIENT_ID,
}
```

### Custom Provider

```typescript
upstream: {
  provider: 'custom',
  apiKey: 'your-client-secret',
  clientId: 'your-client-id',
  authorizationEndpoint: 'https://auth.example.com/authorize',
  tokenEndpoint: 'https://auth.example.com/token',
}
```

## PKCE Utilities

The package also exports PKCE utilities:

```typescript
import { generatePkce, verifyCodeChallenge } from '@dotdo/oauth/pkce'

// Generate PKCE pair
const { verifier, challenge } = await generatePkce()

// Verify during token exchange
const valid = await verifyCodeChallenge(verifier, challenge, 'S256')
```

## Architecture

This package is designed as the **leaf** in the dependency tree:

```
@dotdo/oauth (this package - no deps on oauth.do or @dotdo/do)
     ↑
oauth.do (depends on @dotdo/oauth)
     ↑
@dotdo/do (depends on oauth.do, provides DOAuthStorage)
```

This breaks the circular dependency that would otherwise exist between oauth.do (needs storage) and @dotdo/do (needs auth).

## License

MIT
