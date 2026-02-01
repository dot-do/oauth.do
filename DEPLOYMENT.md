# Deploying the OAuth 2.1 Server

This guide covers deploying the OAuth 2.1 authorization server to Cloudflare Workers.

## Architecture Overview

The OAuth server runs as a Cloudflare Worker with a Durable Object for persistent storage:

- **Worker** (`workers/oauth/index.ts`) - HTTP routing, rate limiting, RPC methods
- **Durable Object** (`workers/oauth/oauth-do.ts`) - OAuth 2.1 endpoints with SQLite storage
- **Core library** (`@dotdo/oauth`) - OAuth 2.1 implementation, storage adapters, JWT signing

## Prerequisites

1. Cloudflare account with Workers enabled
2. WorkOS account (for upstream authentication)
3. Wrangler CLI installed (`npm install -g wrangler`)
4. Domain configured in Cloudflare (e.g., `oauth.do`)

## Required Secrets

Set these using `wrangler secret put <SECRET_NAME>`:

| Secret | Description | Required |
|--------|-------------|----------|
| `WORKOS_API_KEY` | WorkOS API key from Dashboard > API Keys | Yes |
| `WORKOS_COOKIE_PASSWORD` | 32+ character secret for cookie encryption | Yes |
| `SIGNING_KEY_JWK` | RSA private key as JWK JSON (optional - auto-generated if not set) | No |
| `STRIPE_SECRET_KEY` | Stripe secret key for billing integration | No |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook signing secret | No |

```bash
# Set required secrets
wrangler secret put WORKOS_API_KEY
wrangler secret put WORKOS_COOKIE_PASSWORD

# Optional: Set pre-generated signing key for key stability across deployments
# If not set, a key is generated and persisted in Durable Object storage
wrangler secret put SIGNING_KEY_JWK
```

### Generating a Signing Key

If you want to provide your own signing key (recommended for production):

```javascript
// Generate RSA key pair (run in Node.js)
const { generateKeyPairSync } = require('crypto')
const { privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  privateKeyEncoding: { type: 'pkcs8', format: 'jwk' }
})
privateKey.kid = 'key-' + Date.now()
privateKey.alg = 'RS256'
console.log(JSON.stringify(privateKey))
```

## Environment Variables

Configure in `wrangler.jsonc` under `vars`:

```jsonc
{
  "vars": {
    // WorkOS OAuth App client ID
    "WORKOS_CLIENT_ID": "client_01XXXXXXXXXXXXXXXXXX",
    
    // Callback URL registered in WorkOS
    "REDIRECT_URI": "https://oauth.do/callback",
    
    // CORS allowed origins (comma-separated)
    "ALLOWED_ORIGINS": "https://oauth.do,https://myapp.com",
    
    // Branding for the auth UI
    "APP_NAME": "oauth.do",
    "APP_TAGLINE": "Universal Authentication"
  }
}
```

## WorkOS Configuration

1. **Create a WorkOS account** at [workos.com](https://workos.com)

2. **Create an OAuth Application**:
   - Go to WorkOS Dashboard > Authentication > AuthKit
   - Note the Client ID (`client_01...`)
   - Copy the API Key from Dashboard > API Keys

3. **Configure Redirect URIs**:
   - Add your callback URL: `https://oauth.do/callback`
   - For development: `http://localhost:8787/callback`

4. **Configure Authentication Methods**:
   - Enable desired SSO providers (Google, GitHub, etc.)
   - Configure enterprise SSO if needed

## Wrangler Configuration

The `wrangler.jsonc` file configures the Worker deployment:

```jsonc
{
  "name": "oauth",
  "main": "index.ts",
  "compatibility_date": "2025-01-01",
  "compatibility_flags": ["nodejs_compat"],
  
  // Durable Object for persistent storage
  "durable_objects": {
    "bindings": [{
      "name": "OAUTH_DO",
      "class_name": "OAuthDO"
    }]
  },
  
  // Required migration for SQLite storage
  "migrations": [{
    "tag": "v1",
    "new_sqlite_classes": ["OAuthDO"]
  }],
  
  // Rate limiting (prevents abuse)
  "ratelimits": [
    {
      "name": "RATE_LIMITER",
      "namespace_id": 1001,
      "simple": { "limit": 100, "period": 60 }
    },
    {
      "name": "RATE_LIMITER_STRICT",
      "namespace_id": 1002,
      "simple": { "limit": 20, "period": 60 }
    }
  ],
  
  // Custom domain routes
  "routes": [
    { "pattern": "oauth.do/*", "zone_name": "oauth.do" }
  ]
}
```

## Storage Options

The server supports multiple storage backends:

### Durable Object SQLite (Recommended for Production)

Used automatically when the Durable Object binding is configured. Provides:
- Persistent storage across requests
- SQLite for efficient queries
- Automatic schema migrations
- No external database required

### Collections Storage

For integration with `collections.do`:

```typescript
import { CollectionsOAuthStorage } from '@dotdo/oauth'
const storage = new CollectionsOAuthStorage(sql)
```

### Memory Storage (Development Only)

For local development and testing:

```typescript
import { MemoryOAuthStorage } from '@dotdo/oauth'
const storage = new MemoryOAuthStorage()
```

## Deployment

### First-Time Deployment

```bash
# Navigate to worker directory
cd workers/oauth

# Install dependencies
pnpm install

# Deploy (creates Durable Object namespace)
wrangler deploy

# Set secrets
wrangler secret put WORKOS_API_KEY
wrangler secret put WORKOS_COOKIE_PASSWORD
```

### Updating Deployment

```bash
# Deploy changes
wrangler deploy
```

### Local Development

```bash
# Start local development server
wrangler dev

# The server runs at http://localhost:8787
```

## Verifying Deployment

After deployment, verify the server is running:

```bash
# Check server metadata
curl https://oauth.do/.well-known/oauth-authorization-server

# Expected response includes:
# - issuer
# - authorization_endpoint
# - token_endpoint
# - jwks_uri
```

## OAuth 2.1 Endpoints

The server exposes these endpoints:

| Endpoint | Description |
|----------|-------------|
| `/.well-known/oauth-authorization-server` | Server metadata (RFC 8414) |
| `/.well-known/jwks.json` | Public signing keys |
| `/authorize` | Authorization endpoint |
| `/token` | Token endpoint |
| `/introspect` | Token introspection (RFC 7662) |
| `/revoke` | Token revocation (RFC 7009) |
| `/register` | Dynamic client registration (RFC 7591) |
| `/userinfo` | OpenID Connect UserInfo |

## Multi-Tenant Configuration

The server supports multi-tenant deployments via the `X-Issuer` header:

```typescript
// Other services can proxy OAuth with their own issuer
const response = await fetch('https://oauth.do/token', {
  headers: { 'X-Issuer': 'https://myapp.com' }
})
// Tokens will have iss: "https://myapp.com"
```

Configure trusted issuers in the server config:

```typescript
createOAuth21Server({
  trustedIssuers: ['https://oauth.do', 'https://myapp.com']
})
```

## Troubleshooting

### "WORKOS_API_KEY is not set"
Run `wrangler secret put WORKOS_API_KEY` and enter your WorkOS API key.

### "Invalid redirect_uri"
Ensure the redirect URI is registered in WorkOS Dashboard and matches exactly.

### Token validation fails
Check that the issuer URL matches between token generation and validation.

### Rate limit errors
The server applies rate limiting:
- General endpoints: 100 requests/minute per IP
- Sensitive endpoints (`/token`, `/register`): 20 requests/minute per IP

## Security Considerations

1. **Always use HTTPS** in production (enforced by default)
2. **Rotate signing keys** periodically by updating `SIGNING_KEY_JWK`
3. **Use strong secrets** - `WORKOS_COOKIE_PASSWORD` should be 32+ random characters
4. **Configure CORS** - restrict `ALLOWED_ORIGINS` to your domains
5. **Enable rate limiting** - prevents brute force attacks
6. **Review client registrations** - consider requiring authentication for `/register`
