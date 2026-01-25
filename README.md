# oauth.do

[![npm version](https://img.shields.io/npm/v/oauth.do.svg)](https://www.npmjs.com/package/oauth.do)
[![license](https://img.shields.io/npm/l/oauth.do.svg)](https://github.com/dot-do/oauth.do/blob/main/LICENSE)
[![tests](https://img.shields.io/github/actions/workflow/status/dot-do/oauth.do/test.yml?label=tests)](https://github.com/dot-do/oauth.do/actions)

OAuth authentication SDK and CLI for the .do Platform, wrapping [WorkOS AuthKit](https://workos.com/authkit) with pre-configured defaults and multiple entry points for different environments.

**Why oauth.do?**
- Pre-configured AuthKit settings for .do Platform - works out of the box
- Multiple entry points: SDK, CLI, React components, Hono middleware
- Built-in secure token storage with OS keychain support
- GitHub Device Flow for CLI tools and headless environments

```typescript
import { auth } from 'oauth.do'

const { user, token } = await auth()
console.log(`Hello, ${user.firstName}!`)
```

## Entry Points

oauth.do provides multiple entry points for different environments:

| Import | Environment | Description |
|--------|-------------|-------------|
| `oauth.do` | Universal | Core auth functions (browser, Workers, Node.js) |
| `oauth.do/node` | Node.js only | CLI helpers with keychain storage (uses `keytar`) |
| `oauth.do/react` | React | React components and hooks |
| `oauth.do/hono` | Hono/Workers | Cloudflare Workers middleware |
| `oauth.do/session` | Universal | Session management utilities |

**Important for Cloudflare Workers:** Import from the main `oauth.do` path or `oauth.do/hono`. The `/node` subpath uses native modules (`keytar`) that won't bundle for Workers.

## Getting Started

### Prerequisites

- Node.js 18.0.0 or higher
- WorkOS account (optional - for custom AuthKit configuration)

### Installation

```bash
# npm
npm install oauth.do

# pnpm
pnpm add oauth.do

# yarn
yarn add oauth.do

# bun
bun add oauth.do
```

## CLI

```bash
npx oauth.do           # Login (default)
npx oauth.do login     # Login with device flow
npx oauth.do logout    # Logout
npx oauth.do whoami    # Show current user
npx oauth.do token     # Display token
npx oauth.do status    # Show auth status
```

## SDK

```typescript
import { auth, logout, getToken, isAuthenticated } from 'oauth.do'

// Check authentication
const { user, token } = await auth()

// Logout
await logout(token)

// Get stored token
const token = getToken()

// Check if authenticated
if (await isAuthenticated()) { ... }
```

### Build Auth URL

```typescript
import { buildAuthUrl } from 'oauth.do'

const url = buildAuthUrl({
  redirectUri: 'https://myapp.com/callback',
  scope: 'openid profile email',
})
```

### CLI Login Helper

For building CLIs that need authentication:

```typescript
import { ensureLoggedIn } from 'oauth.do/node'

// Get token (prompts login if needed, auto-opens browser)
const { token, isNewLogin } = await ensureLoggedIn()

// Use token for API calls
const response = await fetch('https://api.example.com', {
  headers: { Authorization: `Bearer ${token}` }
})
```

### Device Authorization Flow

```typescript
import { authorizeDevice, pollForTokens } from 'oauth.do'

const auth = await authorizeDevice()
console.log('Visit:', auth.verification_uri)
console.log('Code:', auth.user_code)

const tokens = await pollForTokens(auth.device_code, auth.interval, auth.expires_in)
```

## GitHub Device Flow

For CLI tools and headless environments that need GitHub authentication without a browser callback.

```typescript
import { startGitHubDeviceFlow, pollGitHubDeviceFlow, getGitHubUser } from 'oauth.do'

// Step 1: Start the device flow
const auth = await startGitHubDeviceFlow({
  clientId: 'Ov23liABCDEFGHIJKLMN',
  scope: 'user:email read:user'  // optional, this is the default
})

console.log(`Visit ${auth.verificationUri} and enter code: ${auth.userCode}`)

// Step 2: Poll for token (blocks until user completes authorization)
const token = await pollGitHubDeviceFlow(auth.deviceCode, {
  clientId: 'Ov23liABCDEFGHIJKLMN',
  interval: auth.interval,
  expiresIn: auth.expiresIn
})

// Step 3: Get user information
const user = await getGitHubUser(token.accessToken)
console.log(`Logged in as ${user.login} (ID: ${user.id})`)
```

### GitHub Device Flow API

#### `startGitHubDeviceFlow(options)`

Initiates the device authorization flow by requesting device and user codes.

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `clientId` | `string` | Yes | GitHub OAuth App client ID |
| `scope` | `string` | No | OAuth scopes (default: `'user:email read:user'`) |
| `fetch` | `typeof fetch` | No | Custom fetch implementation |

Returns `GitHubDeviceAuthResponse` with `deviceCode`, `userCode`, `verificationUri`, `expiresIn`, and `interval`.

#### `pollGitHubDeviceFlow(deviceCode, options)`

Polls GitHub's token endpoint until user completes authorization.

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `clientId` | `string` | Yes | GitHub OAuth App client ID |
| `interval` | `number` | No | Polling interval in seconds (default: 5) |
| `expiresIn` | `number` | No | Expiration time in seconds (default: 900) |
| `fetch` | `typeof fetch` | No | Custom fetch implementation |

Returns `GitHubTokenResponse` with `accessToken`, `tokenType`, and `scope`.

#### `getGitHubUser(accessToken, options?)`

Fetches the authenticated user's profile from GitHub API.

Returns `GitHubUser` with `id`, `login`, `email`, `name`, and `avatarUrl`.

## duckdb-auth Binary

The `duckdb-auth` binary wraps DuckDB with automatic OAuth token injection for authenticated HTTP requests.

```bash
# Run DuckDB with oauth.do authentication
duckdb-auth mydata.db

# Execute authenticated queries
duckdb-auth -c "SELECT * FROM read_json('https://api.example.com/protected/data')"
```

**How it works:**

1. Retrieves your OAuth token from `oauth.do token`
2. Creates DuckDB HTTP secrets with your bearer token
3. Launches DuckDB with authentication pre-configured

If you're not logged in, it will automatically start the login flow before launching DuckDB.

## React Components

Pre-configured React components for authentication, wrapping WorkOS AuthKit widgets.

**Additional dependencies for React:** When using `oauth.do/react`, you need to install React and the auth provider:

```bash
pnpm add react react-dom @mdxui/auth @radix-ui/themes
```

```tsx
import { OAuthDoProvider, useAuth, SignInButton, SignOutButton } from 'oauth.do/react'

// Wrap your app with the provider
function App({ children }) {
  return (
    <OAuthDoProvider>
      {children}
    </OAuthDoProvider>
  )
}

// Use the auth hook
function UserGreeting() {
  const { user, isLoading } = useAuth()

  if (isLoading) return <span>Loading...</span>
  if (!user) return <SignInButton>Sign In</SignInButton>

  return (
    <div>
      <span>Hello, {user.firstName}!</span>
      <SignOutButton>Sign Out</SignOutButton>
    </div>
  )
}
```

### React Widgets

```tsx
import { ApiKeys, UsersManagement, UserProfile, useAuth } from 'oauth.do/react'

function SettingsPage() {
  const { user, getAccessToken } = useAuth()
  if (!user) return <p>Please sign in</p>

  return (
    <div>
      <h2>Profile</h2>
      <UserProfile authToken={getAccessToken} />

      <h2>API Keys</h2>
      <ApiKeys authToken={getAccessToken} />

      <h2>Team Members</h2>
      <UsersManagement authToken={getAccessToken} />
    </div>
  )
}
```

## Hono Middleware

Lightweight JWT authentication middleware for Cloudflare Workers and Hono.

```typescript
import { Hono } from 'hono'
import { auth, requireAuth, apiKey } from 'oauth.do/hono'

const app = new Hono()

// Add auth to all routes (populates c.var.user if authenticated)
app.use('*', auth())

// Public route - auth is optional
app.get('/api/public', (c) => {
  const user = c.var.user
  return c.json({ message: 'Hello', user: user?.email || 'anonymous' })
})

// Protected route - requires authentication
app.use('/api/protected/*', requireAuth())

app.get('/api/protected/data', (c) => {
  return c.json({ secret: 'data', user: c.var.user })
})

// Role-based access
app.use('/api/admin/*', requireAuth({ roles: ['admin'] }))

// Permission-based access
app.use('/api/billing/*', requireAuth({ permissions: ['billing:read', 'billing:write'] }))
```

### API Key Authentication

```typescript
import { apiKey, combined } from 'oauth.do/hono'

// API key only
app.use('/api/v1/*', apiKey({
  verify: async (key, c) => {
    const user = await verifyApiKeyInDatabase(key)
    return user // Return AuthUser or null
  }
}))

// Combined: JWT or API key
app.use('/api/*', combined({
  auth: { cookieName: 'session' },
  apiKey: {
    verify: async (key) => verifyApiKey(key)
  }
}))
```

## Token Storage

```typescript
import { createSecureStorage, KeychainTokenStorage } from 'oauth.do'

// Auto-select best storage (keychain -> secure file)
const storage = createSecureStorage()

// Or use keychain directly
const keychain = new KeychainTokenStorage()
if (await keychain.isAvailable()) {
  await keychain.setToken('...')
}
```

Storage backends:
- `KeychainTokenStorage` - OS keychain (macOS, Windows, Linux)
- `SecureFileTokenStorage` - ~/.oauth.do/token with 0600 permissions
- `MemoryTokenStorage` - In-memory (testing)
- `LocalStorageTokenStorage` - Browser localStorage

## Configuration

```typescript
import { configure } from 'oauth.do'

configure({
  apiUrl: 'https://apis.do',
  clientId: 'your-client-id',
  authKitDomain: 'login.oauth.do'
})
```

## Environment Variables

- `ORG_AI_TOKEN` - Authentication token
- `OAUTH_API_URL` - API base URL (default: `https://apis.do`)
- `OAUTH_CLIENT_ID` - OAuth client ID
- `OAUTH_AUTHKIT_DOMAIN` - AuthKit domain (default: `login.oauth.do`)

## License

MIT
