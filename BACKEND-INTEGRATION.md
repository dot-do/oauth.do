# Backend Integration Status

## Current Status

The `oauth.do` SDK has been implemented but **does not have corresponding backend endpoints** yet. The backend uses WorkOS AuthKit with a different authentication flow than what the SDK expects.

## Missing Backend Endpoints

### 1. GET /me (or /api/auth/me)
**Status**: ❌ Not Implemented
**Expected by**: `auth()` function in oauth.do SDK
**Purpose**: Get current authenticated user information

**Expected Request**:
```http
GET /me HTTP/1.1
Host: apis.do
Authorization: Bearer <token>
```

**Expected Response**:
```json
{
  "id": "user_123",
  "email": "user@example.com",
  "name": "John Doe"
}
```

**Current Situation**:
- Referenced in `workers/auth/TODO.md` but not implemented
- Auth worker is RPC-only and doesn't expose HTTP endpoints
- No worker currently serves this endpoint

### 2. POST /login (Credentials-based)
**Status**: ⚠️ Different Implementation
**Expected by**: `login()` function in oauth.do SDK
**Purpose**: Login with email/password credentials

**Expected Request**:
```http
POST /login HTTP/1.1
Host: apis.do
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```

**Expected Response**:
```json
{
  "user": {
    "id": "user_123",
    "email": "user@example.com",
    "name": "John Doe"
  },
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Current Implementation** (`workers/oauth/src/index.ts`):
- POST /login exists but uses **WorkOS AuthKit redirect flow**
- Expects `{ redirect_uri: string }` not credentials
- Returns 302 redirect to WorkOS, not JSON with token
- Cannot be used by the oauth.do SDK as-is

### 3. POST /logout
**Status**: ⚠️ Different Implementation
**Expected by**: `logout()` function in oauth.do SDK
**Purpose**: Logout and clear session

**Expected Request**:
```http
POST /logout HTTP/1.1
Host: apis.do
Authorization: Bearer <token>
```

**Expected Response**:
```http
HTTP/1.1 200 OK
```

**Current Implementation** (`workers/oauth/src/index.ts`):
- POST /logout exists
- Expects `{ redirect_uri?: string }`
- Returns 302 redirect, not 200 OK
- Clears cookies but expects redirect flow

### 4. POST /device/authorize (Device Authorization)
**Status**: ❌ Not Implemented
**Expected by**: `authorizeDevice()` function in oauth.do SDK
**Domain**: login.oauth.do
**Purpose**: Initiate OAuth 2.0 Device Authorization Grant flow

**Expected Request**:
```http
POST /device/authorize HTTP/1.1
Host: login.oauth.do
Content-Type: application/x-www-form-urlencoded

client_id=platform.do
```

**Expected Response**:
```json
{
  "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
  "user_code": "WDJB-MJHT",
  "verification_uri": "https://login.oauth.do/device",
  "verification_uri_complete": "https://login.oauth.do/device?user_code=WDJB-MJHT",
  "expires_in": 900,
  "interval": 5
}
```

**Current Situation**:
- No implementation exists in any worker
- Would need to integrate with WorkOS device flow or implement custom

### 5. POST /device/token (Device Token Exchange)
**Status**: ❌ Not Implemented
**Expected by**: `pollForTokens()` function in oauth.do SDK
**Domain**: login.oauth.do
**Purpose**: Poll for access token after device authorization

**Expected Request**:
```http
POST /device/token HTTP/1.1
Host: login.oauth.do
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:device_code&
device_code=GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS&
client_id=platform.do
```

**Expected Response** (Pending):
```json
{
  "error": "authorization_pending"
}
```

**Expected Response** (Success):
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "user": {
    "id": "user_123",
    "email": "user@example.com",
    "name": "John Doe"
  }
}
```

**Current Situation**:
- No implementation exists in any worker
- Would need custom implementation or WorkOS integration

## Existing Backend Architecture

### workers/oauth (oauth.do domain)
**Routes**:
- ✅ POST /login - WorkOS AuthKit redirect flow
- ✅ POST /signup - WorkOS AuthKit signup flow
- ✅ POST /logout - Clears session with redirect
- ✅ GET /auth/callback - WorkOS callback handler
- ✅ GET /auth/set-cookies - Sets cookies on apis.do domain
- ✅ GET /health - Health check

**Flow**:
1. Client POST to /login with `{ redirect_uri: "https://example.com" }`
2. Worker creates OAuth state, stores in KV
3. Redirects to WorkOS AuthKit login page
4. User authenticates on WorkOS
5. WorkOS redirects to /auth/callback
6. Worker exchanges code for WorkOS tokens
7. Creates signed JWT token
8. Redirects to apis.do /auth/set-cookies
9. Sets auth cookies on apis.do domain
10. Redirects to original redirect_uri

**Architecture**:
- OAuth flow is redirect-based (browser)
- Not suitable for CLI or server-to-server
- Uses WorkOS for actual authentication
- Tokens are stored in httpOnly cookies

### workers/auth (RPC-only)
**RPC Methods**:
- `parseAuthCookies(cookies)` - Parse and validate cookies
- `generateAuthCookies(userData)` - Generate auth cookies
- `clearAuthCookies()` - Clear cookies for logout

**Architecture**:
- RPC-only (no HTTP endpoints)
- Uses iron-session for encrypted cookies
- Three-layer security: Token, Session, Settings
- No REST API exposed

## What Needs to Be Done

### Option 1: Adapt Backend to Support SDK (Recommended)

Create new endpoints in a dedicated worker to support the oauth.do SDK:

1. **Create `/me` endpoint** in workers/oauth or workers/api
   - Parse Authorization header
   - Verify JWT token
   - Return user information

2. **Add credentials-based `/login`** endpoint
   - New route: POST /api/auth/login
   - Accept email/password
   - Integrate with WorkOS or custom auth
   - Return JWT token in JSON (not cookie redirect)

3. **Implement device authorization flow**
   - New worker or routes in workers/oauth
   - Implement RFC 8628 (OAuth 2.0 Device Grant)
   - Store device codes in KV
   - Poll mechanism for token exchange

4. **Update `/logout` endpoint**
   - Support both redirect flow and API flow
   - Return 200 OK for API clients
   - Clear tokens properly

### Option 2: Adapt SDK to Match Backend

Modify oauth.do SDK to work with existing WorkOS flow:

1. **Remove credentials-based login**
   - Use redirect flow instead
   - Open browser for authentication
   - Handle OAuth callbacks

2. **Remove device authorization**
   - Use standard OAuth redirect flow
   - May not work well for CLI

3. **Update `/me` implementation**
   - Use cookies instead of Bearer tokens
   - Or add header-based auth to backend

### Option 3: Dual Mode Support

Support both authentication methods:

1. **API Mode** (for CLIs, SDKs)
   - Device authorization flow
   - JWT tokens in headers
   - GET /me for user info

2. **Browser Mode** (for web apps)
   - WorkOS AuthKit redirect flow
   - Cookies for authentication
   - Existing endpoints

## Recommendations

**For CLI and SDK support**, we need **Option 1** - implement the missing endpoints:

1. **High Priority**:
   - GET /me or /api/auth/me
   - POST /device/authorize
   - POST /device/token

2. **Medium Priority**:
   - Update POST /logout to support API mode
   - Add credentials-based login (if needed)

3. **Implementation Notes**:
   - Device flow should integrate with WorkOS if possible
   - Store device codes in KV with expiration
   - Use same JWT signing as WorkOS flow
   - Maintain cookie-based auth for browsers

## E2E Testing Strategy

Once endpoints are implemented:

1. **Unit Tests** (already complete)
   - Mock fetch responses
   - Test SDK functions in isolation

2. **Integration Tests**
   - Test against local dev environment
   - Use real KV, real token signing
   - Mock WorkOS API calls

3. **E2E Tests** (need to create)
   - Test against deployed workers
   - Use real WorkOS (test mode)
   - Validate full auth flow
   - Test CLI login flow
   - Test SDK usage

## WorkOS AuthKit Configuration

**Domain Configuration Needed**:
- login.oauth.do - AuthKit domain for device flow
- oauth.do - OAuth callback domain
- apis.do - API domain for endpoints

**WorkOS Settings**:
- Client ID: Set in WORKOS_CLIENT_ID
- API Key: Set in WORKOS_API_KEY
- Redirect URIs:
  - https://oauth.do/auth/callback
  - https://apis.do/auth/callback (if needed)

## Implementation Complete! ✅

### What Was Implemented

**Option 3: Dual Mode Support** - Completed!

1. **✅ GET /me** - `workers/oauth/src/index.ts:347`
   - Supports both Bearer tokens and cookies
   - Works for API and browser modes

2. **✅ Device Authorization Flow**:
   - POST /device/authorize - `workers/oauth/src/index.ts:422`
   - POST /device/token - `workers/oauth/src/index.ts:483`
   - GET /device - `workers/oauth/src/index.ts:597` (user verification page)
   - POST /device/verify - `workers/oauth/src/index.ts:787`
   - GET /device/callback - `workers/oauth/src/index.ts:847`

3. **✅ Updated Endpoints**:
   - POST /login - `workers/oauth/src/index.ts:32` (dual mode support)
   - POST /logout - `workers/oauth/src/index.ts:157` (dual mode support)
   - GET /auth/callback - `workers/oauth/src/index.ts:202` (supports device flow)

4. **✅ Updated SDK**:
   - Default domain changed to `oauth.do` (not `login.oauth.do`)
   - Default client_id set to `platform.do`
   - Configuration updated in both oauth.do and platform.do CLIs

### Documentation

- **workers/oauth/IMPLEMENTATION.md** - Complete implementation details
- **oauth.do/BACKEND-INTEGRATION.md** - This file (integration status)
- **oauth.do/README.md** - Updated with correct domains

### Architecture

```
┌─────────────┐
│  CLI/SDK    │ (platform.do, oauth.do SDK)
│  API Mode   │
└─────────────┘
       │
       │ Bearer Token (JWT)
       │
       ▼
┌─────────────┐         ┌──────────┐
│  oauth.do   │◄────────│  WorkOS  │
│   Worker    │─────────►│ AuthKit  │
└─────────────┘         └──────────┘
       │
       │ Cookies (encrypted)
       │
       ▼
┌─────────────┐
│   Browser   │
│  Web Apps   │
└─────────────┘
```

### Next Steps

1. ✅ Document current state
2. ✅ Decide on authentication architecture (Dual Mode)
3. ✅ Implement missing endpoints
4. ✅ Update oauth.do SDK
5. ⏳ Build and test locally
6. ⏳ Create E2E tests
7. ⏳ Deploy to staging/production
8. ⏳ Test with WorkOS
9. ⏳ Update documentation with live examples
