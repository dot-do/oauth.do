# oauth.do

OAuth authentication SDK and CLI for .do Platform.

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

### Device Authorization Flow

```typescript
import { authorizeDevice, pollForTokens } from 'oauth.do'

const auth = await authorizeDevice()
console.log('Visit:', auth.verification_uri)
console.log('Code:', auth.user_code)

const tokens = await pollForTokens(auth.device_code, auth.interval, auth.expires_in)
```

## API Keys

```typescript
import { createApiKey, listApiKeys, rotateApiKey, deleteApiKey } from 'oauth.do'

// Create
const key = await createApiKey({ name: 'my-key', expiresIn: '30d' })

// List
const keys = await listApiKeys()

// Rotate
const newKey = await rotateApiKey(key.id)

// Delete
await deleteApiKey(key.id)
```

## Token Storage

```typescript
import { createSecureStorage, KeychainTokenStorage } from 'oauth.do'

// Auto-select best storage (keychain → secure file)
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

- `DO_TOKEN` - Authentication token
- `OAUTH_API_URL` - API base URL (default: `https://apis.do`)
- `OAUTH_CLIENT_ID` - OAuth client ID (default: `oauth.do`)
- `OAUTH_AUTHKIT_DOMAIN` - AuthKit domain (default: `login.oauth.do`)

## License

MIT
