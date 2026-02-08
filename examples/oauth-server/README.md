# Deploy your own OAuth 2.1 Server

This example deploys a full OAuth 2.1 authorization server on Cloudflare Workers using `@dotdo/oauth`. The server can issue access tokens, refresh tokens, and handle the complete OAuth 2.1 flow including PKCE, device flow, dynamic client registration, and token introspection.

## What you get

A single Worker that implements these standard endpoints:

| Endpoint | RFC | Purpose |
|---|---|---|
| `GET /.well-known/oauth-authorization-server` | RFC 8414 | Server metadata discovery |
| `GET /.well-known/jwks.json` | — | JSON Web Key Set |
| `GET /authorize` | RFC 6749 | Authorization endpoint |
| `POST /token` | RFC 6749 | Token endpoint |
| `POST /register` | RFC 7591 | Dynamic client registration |
| `POST /revoke` | RFC 7009 | Token revocation |
| `POST /introspect` | RFC 7662 | Token introspection |
| `GET /userinfo` | OIDC | User info endpoint |
| `POST /device_authorization` | RFC 8628 | Device authorization grant |
| `GET /device` | RFC 8628 | Device verification page |

## Quick start (dev mode)

Dev mode runs without any upstream auth provider. Users log in with email + password directly.

```bash
# Install dependencies
npm install

# Start the server locally
npx wrangler dev
```

The server starts at `http://localhost:8787`. Try the discovery endpoint:

```bash
curl http://localhost:8787/.well-known/oauth-authorization-server | jq
```

### Register a client

```bash
curl -X POST http://localhost:8787/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My App",
    "redirect_uris": ["http://localhost:3000/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none"
  }'
```

Save the `client_id` from the response.

### Authorization flow

1. Open the authorization URL in a browser:

```
http://localhost:8787/authorize?client_id=<CLIENT_ID>&redirect_uri=http://localhost:3000/callback&response_type=code&code_challenge=<CHALLENGE>&code_challenge_method=S256&state=random123
```

2. In dev mode, you'll see a login form. Use `alice@example.com` / `password` or any credentials (with `allowAnyCredentials: true`).

3. After login, you'll be redirected to your callback URL with an authorization code.

4. Exchange the code for tokens:

```bash
curl -X POST http://localhost:8787/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=<AUTH_CODE>&client_id=<CLIENT_ID>&redirect_uri=http://localhost:3000/callback&code_verifier=<VERIFIER>"
```

## Production setup

For production, configure an upstream OAuth provider (WorkOS, Auth0, or Okta) to handle user authentication. Your OAuth server becomes a federation layer that issues its own tokens while delegating login to the upstream provider.

### 1. Set secrets

```bash
wrangler secret put WORKOS_API_KEY
wrangler secret put WORKOS_CLIENT_ID
```

### 2. Update wrangler.jsonc

```jsonc
{
  "vars": {
    "ISSUER": "https://auth.yourdomain.com",
    "DEV_MODE": "false"
  }
}
```

### 3. Deploy

```bash
npx wrangler deploy
```

### 4. Configure your upstream provider

In your WorkOS (or Auth0/Okta) dashboard, add a redirect URI:

```
https://auth.yourdomain.com/callback
```

## Storage backends

This example uses `MemoryOAuthStorage` for simplicity. In production, use a persistent backend:

```ts
// Durable Object SQLite storage (recommended for Workers)
import { DOSQLiteStorage } from '@dotdo/oauth'
const storage = new DOSQLiteStorage(sqlStorage)

// Collections-based storage (uses @dotdo/collections)
import { CollectionsOAuthStorage } from '@dotdo/oauth'
const storage = new CollectionsOAuthStorage(collections)
```

## MCP compatibility

This OAuth server is designed to work with Model Context Protocol (MCP) clients like Claude and ChatGPT. MCP clients discover your server via `/.well-known/oauth-authorization-server`, register dynamically via `/register`, and authenticate via the standard authorization code flow with PKCE.

## Related

- [@dotdo/oauth documentation](https://oauth.do)
- [OAuth 2.1 specification](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1)
- [MCP specification](https://spec.modelcontextprotocol.io)
