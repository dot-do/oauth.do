# Protect a Hono API with oauth.do

This example shows how to add authentication and authorization to a Hono API using the `oauth.do` middleware. It covers every auth pattern the library provides.

## What's included

| Pattern | Middleware | Behavior |
|---|---|---|
| Optional auth | `auth()` | Populates `c.var.user` if a valid JWT is present; does **not** block unauthenticated requests |
| Required auth | `requireAuth()` | Returns `401` if no valid token |
| Smart auth | `assertAuth()` | Redirects browsers to login page; returns `401` JSON for API clients |
| Role-based | `assertRole()` | Requires the user to have at least one of the listed roles |
| Permission-based | `assertPermission()` | Requires the user to have **all** listed permissions |
| API key | `apiKey()` | Authenticates via `X-API-Key` header |
| Combined | `combined()` | Tries JWT first, falls back to API key |
| Session auth | `sessionAuth()` / `requireSession()` | Encrypted cookie sessions with OAuth login flow |

## Quick start

```bash
# Install dependencies
npm install

# Run locally (Cloudflare Workers compatible)
npx wrangler dev

# Or run with Node.js
npx tsx index.ts
```

## How it works

### 1. Install oauth.do

```bash
npm install oauth.do hono jose
```

### 2. Apply the `auth()` middleware globally

```ts
import { Hono } from 'hono'
import { auth } from 'oauth.do/hono'

const app = new Hono()

app.use('*', auth({
  jwksUri: 'https://api.workos.com/sso/jwks/<your-client-id>',
}))
```

This populates `c.var.user`, `c.var.isAuth`, `c.var.userId`, and `c.var.token` on every request. If no valid JWT is present, `c.var.user` is `null` and the request continues.

### 3. Protect individual routes

```ts
import { requireAuth } from 'oauth.do/hono'

app.get('/api/me', requireAuth({ jwksUri: JWKS_URI }), (c) => {
  return c.json(c.var.user)
})
```

### 4. Use API keys for programmatic access

```ts
import { apiKey } from 'oauth.do/hono'

app.get('/api/data', apiKey({
  verify: async (key) => {
    // Look up the key in your database
    return key === 'sk_live_xxx' ? { id: 'svc_1', email: 'bot@acme.co' } : null
  },
}), (c) => {
  return c.json({ data: [1, 2, 3], user: c.var.user })
})
```

## Testing

```bash
# Public endpoint
curl http://localhost:3000/

# Protected endpoint (will return 401)
curl http://localhost:3000/api/me

# With a Bearer token
curl -H "Authorization: Bearer <jwt>" http://localhost:3000/api/me

# With an API key
curl -H "X-API-Key: sk_test_abc123" http://localhost:3000/api/data
```

## Deploy to Cloudflare Workers

```bash
npx wrangler deploy
```

## Context variables

After the `auth()` middleware runs, the following variables are available on every request via `c.var`:

| Variable | Type | Description |
|---|---|---|
| `c.var.user` | `AuthUser \| null` | The authenticated user, or `null` |
| `c.var.userId` | `string \| null` | Shorthand for `user.id` |
| `c.var.isAuth` | `boolean` | Whether the request is authenticated |
| `c.var.token` | `string \| null` | The raw token (JWT or API key) |

## Related

- [oauth.do documentation](https://oauth.do)
- [Hono documentation](https://hono.dev)
- [WorkOS AuthKit](https://workos.com/docs/authkit)
