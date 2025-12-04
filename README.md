# oauth.do

OAuth authentication SDK and CLI for .do Platform with React hooks and components.

## Features

- **Core Auth Functions**: `auth()`, `login()`, `logout()` for API authentication
- **React Integration**: Hooks and components for React applications
- **CLI Authentication**: OAuth 2.0 Device Authorization Grant flow
- **Secure Token Storage**: OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service) with secure file fallback
- **TypeScript**: Full type safety and IntelliSense support

## Installation

```bash
npm install oauth.do
# or
pnpm add oauth.do
# or
yarn add oauth.do
```

## CLI Usage

The oauth.do CLI provides commands for authentication:

### Login

```bash
npx oauth.do login
```

This will:
1. Display a verification URL and code
2. Open your browser automatically
3. Wait for you to authorize the application
4. Save your authentication token securely (OS keychain when available)

### Check Current User

```bash
npx oauth.do whoami
```

### Check Status

```bash
npx oauth.do status
```

Shows authentication status and which storage backend is being used.

### Logout

```bash
npx oauth.do logout
```

### Get Token

```bash
npx oauth.do token
```

## SDK Usage

### Basic Authentication

```typescript
import { auth, login, logout } from 'oauth.do'

// Check current authentication
const { user, token } = await auth()

// Login with credentials
const result = await login({
  email: 'user@example.com',
  password: 'password'
})

// Logout
await logout(token)
```

### Configuration

```typescript
import { configure } from 'oauth.do'

configure({
  apiUrl: 'https://apis.do',
  clientId: 'your-client-id',
  authKitDomain: 'login.oauth.do'
})
```

### Device Authorization Flow

For CLI applications, use the device authorization flow:

```typescript
import { authorizeDevice, pollForTokens } from 'oauth.do'

// Step 1: Get device code
const auth = await authorizeDevice()
console.log('Visit:', auth.verification_uri)
console.log('Enter code:', auth.user_code)

// Step 2: Poll for tokens
const tokens = await pollForTokens(
  auth.device_code,
  auth.interval,
  auth.expires_in
)

console.log('Access token:', tokens.access_token)
```

## CDN Usage

For quick prototyping or simple projects, you can use oauth.do React components directly from a CDN without a build step.

### Option 1: Modern ESM (Recommended)

```html
<!DOCTYPE html>
<html>
<head>
  <script type="importmap">
    {
      "imports": {
        "react": "https://esm.sh/react@18",
        "react-dom/client": "https://esm.sh/react-dom@18/client",
        "oauth.do/react/cdn": "https://unpkg.com/oauth.do@latest/dist/react/oauth.min.js"
      }
    }
  </script>
</head>
<body>
  <div id="root"></div>

  <script type="module">
    import React from 'react'
    import { createRoot } from 'react-dom/client'
    import { AuthProvider, useAuth, Authenticated } from 'oauth.do/react/cdn'

    function App() {
      const { user, loading } = useAuth()

      return React.createElement(AuthProvider, null,
        React.createElement(Authenticated, {
          loading: React.createElement('div', null, 'Loading...')
        },
          React.createElement('div', null,
            `Welcome, ${user?.name || 'Guest'}!`
          )
        )
      )
    }

    const root = createRoot(document.getElementById('root'))
    root.render(React.createElement(App))
  </script>
</body>
</html>
```

### Option 2: Classic Script Tag (IIFE/UMD)

```html
<!DOCTYPE html>
<html>
<head>
  <!-- Load React first -->
  <script crossorigin src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
  <script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>

  <!-- Load oauth.do -->
  <script src="https://unpkg.com/oauth.do@latest/dist/react/oauth.umd.global.js"></script>
</head>
<body>
  <div id="root"></div>

  <script>
    const { AuthProvider, useAuth, Authenticated } = window.OAuthDo

    function App() {
      const { user, loading } = useAuth()

      return React.createElement(AuthProvider, null,
        React.createElement(Authenticated, null,
          React.createElement('div', null,
            'Welcome, ' + (user?.name || 'Guest') + '!'
          )
        )
      )
    }

    const root = ReactDOM.createRoot(document.getElementById('root'))
    root.render(React.createElement(App))
  </script>
</body>
</html>
```

### CDN Providers

oauth.do is available on multiple CDN providers:

- **unpkg**: `https://unpkg.com/oauth.do@latest/dist/react/`
- **jsDelivr**: `https://cdn.jsdelivr.net/npm/oauth.do@latest/dist/react/`
- **esm.sh**: `https://esm.sh/oauth.do@latest`

### Bundle Sizes

- **ESM (Minified)**: ~4 KB
- **UMD (Minified)**: ~38 KB (includes all dependencies)

## React Usage

### Provider Setup

Wrap your app with the `AuthProvider`:

```tsx
import { AuthProvider } from 'oauth.do/react'

function App() {
  return (
    <AuthProvider config={{ apiUrl: 'https://apis.do' }}>
      <YourApp />
    </AuthProvider>
  )
}
```

### Hooks

#### useAuth

Access authentication state and functions:

```tsx
import { useAuth } from 'oauth.do/react'

function MyComponent() {
  const { user, token, loading, error, login, logout } = useAuth()

  if (loading) return <div>Loading...</div>
  if (error) return <div>Error: {error.message}</div>

  return (
    <div>
      {user ? (
        <>
          <p>Welcome, {user.name}!</p>
          <button onClick={logout}>Logout</button>
        </>
      ) : (
        <button onClick={() => login('token')}>Login</button>
      )}
    </div>
  )
}
```

#### useAuthState

Simple authentication state hook:

```tsx
import { useAuthState } from 'oauth.do/react'

function MyComponent() {
  const { user, loading, error } = useAuthState('your-token')

  // ...
}
```

#### useLogin / useLogout

Separate hooks for login and logout:

```tsx
import { useLogin, useLogout } from 'oauth.do/react'

function LoginForm() {
  const { login, loading, error } = useLogin()

  const handleSubmit = async (e) => {
    e.preventDefault()
    await login({ email: '...', password: '...' })
  }

  // ...
}

function LogoutButton() {
  const { logout, loading } = useLogout()

  return (
    <button onClick={() => logout()} disabled={loading}>
      Logout
    </button>
  )
}
```

### Components

#### Authenticated / Unauthenticated

Conditionally render content based on auth state:

```tsx
import { Authenticated, Unauthenticated } from 'oauth.do/react'

function MyApp() {
  return (
    <>
      <Authenticated>
        <Dashboard />
      </Authenticated>

      <Unauthenticated fallback={<Dashboard />}>
        <LoginPage />
      </Unauthenticated>
    </>
  )
}
```

#### LoginButton

Button component that initiates login flow. Supports two modes:

**Redirect mode** - redirects to an OAuth login page:

```tsx
import { LoginButton, buildAuthUrl } from 'oauth.do/react'

function Header() {
  const loginUrl = buildAuthUrl({
    redirectUri: window.location.origin + '/callback',
    scope: 'openid profile email',
  })

  return (
    <LoginButton loginUrl={loginUrl}>
      Sign In
    </LoginButton>
  )
}
```

**Custom mode** - handle login flow yourself:

```tsx
import { LoginButton } from 'oauth.do/react'

function Header() {
  const handleLogin = async () => {
    // Open popup, call API, etc.
    const token = await myCustomLoginFlow()
    return token
  }

  return (
    <LoginButton
      onRequestLogin={handleLogin}
      onLoginComplete={(token) => console.log('Logged in!')}
      onLoginError={(error) => console.error(error)}
    >
      Sign In
    </LoginButton>
  )
}
```

#### LogoutButton

Button component that logs out the user (calls server endpoint and clears local state):

```tsx
import { LogoutButton } from 'oauth.do/react'

function Header() {
  return (
    <LogoutButton
      onLogoutComplete={() => router.push('/')}
      onLogoutError={(error) => console.error(error)}
    >
      Sign Out
    </LogoutButton>
  )
}
```

To only clear local state without calling the server:

```tsx
<LogoutButton callServer={false}>Sign Out</LogoutButton>
```

#### UserDisplay

Display user information:

```tsx
import { UserDisplay } from 'oauth.do/react'

function Header() {
  return (
    <UserDisplay
      render={(user) => (
        <div>
          <img src={user.avatar} />
          <span>{user.name}</span>
        </div>
      )}
      fallback={<span>Not logged in</span>}
    />
  )
}
```

## Token Storage

### Secure Storage (Recommended)

Uses OS keychain when available, falls back to secure file storage:

```typescript
import { createSecureStorage } from 'oauth.do'

const storage = createSecureStorage()

await storage.setToken('token')
const token = await storage.getToken()
await storage.removeToken()
```

### Keychain Storage

Direct access to OS credential manager:

```typescript
import { KeychainTokenStorage } from 'oauth.do'

const storage = new KeychainTokenStorage()

// Check if keychain is available
if (await storage.isAvailable()) {
  await storage.setToken('token')
}
```

### Secure File Storage

File-based storage with proper permissions (0600):

```typescript
import { SecureFileTokenStorage } from 'oauth.do'

const storage = new SecureFileTokenStorage()
// Stores at ~/.oauth.do/token with restricted permissions
```

### File Storage (Legacy)

```typescript
import { FileTokenStorage } from 'oauth.do'

const storage = new FileTokenStorage()

await storage.setToken('token')
const token = await storage.getToken()
await storage.removeToken()
```

### Memory Storage

```typescript
import { MemoryTokenStorage } from 'oauth.do'

const storage = new MemoryTokenStorage()
// Same API as FileTokenStorage
```

### LocalStorage (Browser)

```typescript
import { LocalStorageTokenStorage } from 'oauth.do'

const storage = new LocalStorageTokenStorage()
// Same API as FileTokenStorage
```

## Environment Variables

- `OAUTH_API_URL` - API base URL (default: `https://apis.do`)
- `OAUTH_CLIENT_ID` - OAuth client ID (default: `oauth.do`)
- `OAUTH_AUTHKIT_DOMAIN` - AuthKit domain (default: `login.oauth.do`)
- `DO_TOKEN` - Authentication token

## TypeScript

Full TypeScript support with type definitions:

```typescript
import type {
  User,
  AuthResult,
  OAuthConfig,
  TokenStorage,
  DeviceAuthorizationResponse,
  TokenResponse
} from 'oauth.do'
```

## Security

oauth.do follows security best practices:

- **OS Keychain Integration**: Tokens are stored in the OS credential manager when available (macOS Keychain, Windows Credential Manager, Linux Secret Service)
- **Secure File Permissions**: When file storage is used, files are created with 0600 permissions (owner read/write only)
- **Automatic Migration**: Existing tokens are automatically migrated from insecure file storage to keychain
- **Server-side Logout**: LogoutButton calls the server endpoint to invalidate tokens

## License

MIT
