# oauth.do

OAuth authentication SDK and CLI for org.ai identity.

## Install

```bash
npm install oauth.do
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
import { auth, login, logout, getToken, isAuthenticated } from 'oauth.do'

// Check authentication
const { user, token } = await auth()

// Login
const result = await login({ email: '...', password: '...' })

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

## React Components

Pre-configured React components for authentication, wrapping WorkOS AuthKit widgets.

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
import { createSecureStorage, KeychainTokenStorage } from 'oauth.do/node'

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
