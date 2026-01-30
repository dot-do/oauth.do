# oauth.do Documentation

Universal authentication for the .do ecosystem.

## React

Install the oauth.do package:

```bash
npm install oauth.do
```

Use the auth hook in your components:

```tsx
import { useAuth } from 'oauth.do'

function App() {
  const { user, isLoading, signIn, signOut } = useAuth()

  if (isLoading) return <div>Loading...</div>

  if (!user) {
    return <button onClick={() => signIn()}>Sign In</button>
  }

  return (
    <div>
      <p>Welcome, {user.email}</p>
      <button onClick={() => signOut()}>Sign Out</button>
    </div>
  )
}
```

## Node.js

Install the SDK:

```bash
npm install @dotdo/oauth
```

Ensure user is logged in and get a token:

```typescript
import { ensureLoggedIn } from '@dotdo/oauth'

const { token, user } = await ensureLoggedIn()

// Use token to call authenticated APIs
const response = await fetch('https://api.example.do/data', {
  headers: {
    Authorization: `Bearer ${token}`,
  },
})
```

Validate tokens server-side:

```typescript
import { validateToken } from '@dotdo/oauth'

const { valid, claims } = await validateToken(token)

if (valid) {
  console.log('User:', claims.sub)
  console.log('Email:', claims.email)
}
```

## CLI

Login via the command line:

```bash
npx oauth.do login
```

Check current session:

```bash
npx oauth.do whoami
```

Logout:

```bash
npx oauth.do logout
```

## API Endpoints

### Authorization Server Metadata

```
GET /.well-known/oauth-authorization-server
```

Returns OAuth 2.1 server metadata including supported endpoints and capabilities.

### Token Introspection

```
POST /introspect
Content-Type: application/x-www-form-urlencoded

token=<access_token>
```

Returns token validity and claims.

### Token Exchange

```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
code=<code>
redirect_uri=<redirect_uri>
code_verifier=<pkce_verifier>
```

Exchange authorization code for access token.
