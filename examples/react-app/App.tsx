/**
 * React App Example with oauth.do Authentication
 *
 * Demonstrates using oauth.do React components for:
 * - User authentication with useAuth hook
 * - Sign in/out buttons
 * - Protecting components based on auth state
 * - Accessing user information
 */

import React from 'react'
import {
  OAuthDoProvider,
  useAuth,
  SignInButton,
  SignOutButton,
  UserProfile,
  ApiKeys,
} from 'oauth.do/react'

// ============================================================================
// Main App with Provider
// ============================================================================

export default function App() {
  return (
    <OAuthDoProvider>
      <div style={{ padding: '2rem', fontFamily: 'system-ui, sans-serif' }}>
        <h1>oauth.do React Example</h1>
        <AuthDemo />
      </div>
    </OAuthDoProvider>
  )
}

// ============================================================================
// Auth Demo Component
// ============================================================================

function AuthDemo() {
  const { user, isLoading, signIn, signOut, getAccessToken } = useAuth()

  if (isLoading) {
    return <p>Loading...</p>
  }

  if (!user) {
    return (
      <div>
        <p>You are not signed in.</p>
        <SignInButton className="btn">Sign In with oauth.do</SignInButton>

        {/* Or use the signIn function directly */}
        <button onClick={signIn} style={{ marginLeft: '1rem' }}>
          Sign In (programmatic)
        </button>
      </div>
    )
  }

  return (
    <div>
      <UserGreeting />
      <hr style={{ margin: '2rem 0' }} />
      <ProtectedContent />
      <hr style={{ margin: '2rem 0' }} />
      <SignOutButton className="btn">Sign Out</SignOutButton>
    </div>
  )
}

// ============================================================================
// User Greeting Component
// ============================================================================

function UserGreeting() {
  const { user } = useAuth()

  if (!user) return null

  return (
    <div>
      <h2>Welcome, {user.firstName || user.email}!</h2>
      <pre style={{ background: '#f5f5f5', padding: '1rem', borderRadius: '4px' }}>
        {JSON.stringify(user, null, 2)}
      </pre>
    </div>
  )
}

// ============================================================================
// Protected Content Component
// ============================================================================

function ProtectedContent() {
  const { user, getAccessToken, organizationId, roles, permissions } = useAuth()

  if (!user) return null

  const handleApiCall = async () => {
    const token = await getAccessToken()
    console.log('Making API call with token:', token.substring(0, 20) + '...')

    const response = await fetch('https://apis.do/user', {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    })
    const data = await response.json()
    console.log('API Response:', data)
    alert('Check console for API response')
  }

  return (
    <div>
      <h3>Protected Content</h3>
      <p>This content is only visible to authenticated users.</p>

      <h4>Auth Details</h4>
      <ul>
        <li>User ID: {user.id}</li>
        <li>Email: {user.email}</li>
        <li>Organization: {organizationId || 'None'}</li>
        <li>Roles: {roles?.join(', ') || 'None'}</li>
        <li>Permissions: {permissions?.join(', ') || 'None'}</li>
      </ul>

      <button onClick={handleApiCall} style={{ marginTop: '1rem' }}>
        Make Authenticated API Call
      </button>
    </div>
  )
}

// ============================================================================
// Optional: Profile Page Component
// ============================================================================

export function ProfilePage() {
  const { user, getAccessToken } = useAuth()

  if (!user) {
    return <p>Please sign in to view your profile.</p>
  }

  return (
    <div>
      <h2>User Profile</h2>
      <UserProfile authToken={getAccessToken} />
    </div>
  )
}

// ============================================================================
// Optional: API Keys Page Component
// ============================================================================

export function ApiKeysPage() {
  const { user, getAccessToken } = useAuth()

  if (!user) {
    return <p>Please sign in to manage API keys.</p>
  }

  return (
    <div>
      <h2>API Keys</h2>
      <ApiKeys authToken={getAccessToken} />
    </div>
  )
}
