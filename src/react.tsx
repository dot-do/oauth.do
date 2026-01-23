/**
 * oauth.do/react - React components for authentication
 *
 * Wraps WorkOS AuthKit widgets with oauth.do configuration.
 * Pre-configured with oauth.do WorkOS client ID.
 *
 * @packageDocumentation
 */

'use client'

import {
  WorkOsWidgets,
  ApiKeys as WorkOSApiKeys,
  UserManagement as WorkOSUserManagement,
  UserProfile as WorkOSUserProfile,
  type AuthToken
} from '@workos-inc/widgets'
import {
  AuthKitProvider as WorkOSAuthKitProvider,
  useAuth as useWorkOSAuth,
  type AuthKitProviderProps
} from '@workos-inc/authkit-react'
import React, { createContext, useContext, type ReactNode } from 'react'

// oauth.do default configuration
const OAUTH_DO_CONFIG = {
  clientId: 'client_01JQYTRXK9ZPD8JPJTKDCRB656',
  apiUrl: 'https://apis.do',
  authKitDomain: 'login.oauth.do',
}

// ═══════════════════════════════════════════════════════════════════════════
// Context
// ═══════════════════════════════════════════════════════════════════════════

interface OAuthDoContextValue {
  clientId: string
  apiUrl: string
  authKitDomain: string
}

const OAuthDoContext = createContext<OAuthDoContextValue>(OAUTH_DO_CONFIG)

export function useOAuthDoConfig(): OAuthDoContextValue {
  return useContext(OAuthDoContext)
}

// ═══════════════════════════════════════════════════════════════════════════
// Provider
// ═══════════════════════════════════════════════════════════════════════════

export interface OAuthDoProviderProps {
  children: ReactNode
  /** Override the default client ID */
  clientId?: string
  /** Override the API URL */
  apiUrl?: string
  /** Override the AuthKit domain */
  authKitDomain?: string
  /** Initial auth state from server (for SSR hydration) */
  initialAuth?: AuthKitProviderProps['initialAuth']
}

/**
 * OAuth.do Provider - wraps your app with authentication context
 *
 * @example
 * ```tsx
 * import { OAuthDoProvider } from 'oauth.do/react'
 *
 * export default function App({ children }) {
 *   return (
 *     <OAuthDoProvider>
 *       {children}
 *     </OAuthDoProvider>
 *   )
 * }
 * ```
 */
export function OAuthDoProvider({
  children,
  clientId = OAUTH_DO_CONFIG.clientId,
  apiUrl = OAUTH_DO_CONFIG.apiUrl,
  authKitDomain = OAUTH_DO_CONFIG.authKitDomain,
  initialAuth,
}: OAuthDoProviderProps): JSX.Element {
  const config = { clientId, apiUrl, authKitDomain }

  return (
    <OAuthDoContext.Provider value={config}>
      <WorkOSAuthKitProvider
        clientId={clientId}
        initialAuth={initialAuth}
      >
        <WorkOsWidgets>
          {children}
        </WorkOsWidgets>
      </WorkOSAuthKitProvider>
    </OAuthDoContext.Provider>
  )
}

// ═══════════════════════════════════════════════════════════════════════════
// Hooks
// ═══════════════════════════════════════════════════════════════════════════

/**
 * useAuth hook - access current user and auth state
 *
 * @example
 * ```tsx
 * import { useAuth } from 'oauth.do/react'
 *
 * function UserGreeting() {
 *   const { user, isLoading } = useAuth()
 *
 *   if (isLoading) return <span>Loading...</span>
 *   if (!user) return <span>Please sign in</span>
 *
 *   return <span>Hello, {user.firstName}!</span>
 * }
 * ```
 */
export function useAuth() {
  return useWorkOSAuth()
}

// ═══════════════════════════════════════════════════════════════════════════
// Widgets
// ═══════════════════════════════════════════════════════════════════════════

export interface ApiKeysProps {
  /** Auth token for the widget (from useAuth().getAccessToken or server-generated) */
  authToken: AuthToken
}

/**
 * API Keys Widget - manage API keys for your organization
 *
 * Requires the `widgets:api-keys:manage` permission.
 *
 * @example
 * ```tsx
 * import { ApiKeys, useAuth } from 'oauth.do/react'
 *
 * function ApiKeysPage() {
 *   const { user, getAccessToken } = useAuth()
 *   if (!user) return <p>Please sign in</p>
 *
 *   return <ApiKeys authToken={getAccessToken} />
 * }
 * ```
 */
export function ApiKeys({ authToken }: ApiKeysProps): JSX.Element {
  return <WorkOSApiKeys authToken={authToken} />
}

export interface UserManagementProps {
  /** Auth token for the widget */
  authToken: AuthToken
}

/**
 * User Management Widget - invite, remove, and manage users
 *
 * @example
 * ```tsx
 * import { UserManagement, useAuth } from 'oauth.do/react'
 *
 * function UsersPage() {
 *   const { user, getAccessToken } = useAuth()
 *   if (!user) return <p>Please sign in</p>
 *
 *   return <UserManagement authToken={getAccessToken} />
 * }
 * ```
 */
export function UserManagement({ authToken }: UserManagementProps): JSX.Element {
  return <WorkOSUserManagement authToken={authToken} />
}

export interface UserProfileProps {
  /** Auth token for the widget */
  authToken: AuthToken
}

/**
 * User Profile Widget - view and edit user profile
 *
 * @example
 * ```tsx
 * import { UserProfile, useAuth } from 'oauth.do/react'
 *
 * function ProfilePage() {
 *   const { user, getAccessToken } = useAuth()
 *   if (!user) return <p>Please sign in</p>
 *
 *   return <UserProfile authToken={getAccessToken} />
 * }
 * ```
 */
export function UserProfile({ authToken }: UserProfileProps): JSX.Element {
  return <WorkOSUserProfile authToken={authToken} />
}

// ═══════════════════════════════════════════════════════════════════════════
// Login Components
// ═══════════════════════════════════════════════════════════════════════════

export interface SignInButtonProps {
  children?: ReactNode
  className?: string
  redirectTo?: string
}

/**
 * Sign In Button - redirects to oauth.do login
 *
 * @example
 * ```tsx
 * import { SignInButton } from 'oauth.do/react'
 *
 * function Header() {
 *   return <SignInButton>Sign In</SignInButton>
 * }
 * ```
 */
export function SignInButton({
  children = 'Sign In',
  className,
  redirectTo = typeof window !== 'undefined' ? window.location.href : '/',
}: SignInButtonProps): JSX.Element {
  const { authKitDomain, clientId } = useOAuthDoConfig()

  const handleClick = () => {
    const url = new URL(`https://${authKitDomain}`)
    url.searchParams.set('client_id', clientId)
    url.searchParams.set('redirect_uri', redirectTo)
    url.searchParams.set('response_type', 'code')
    window.location.href = url.toString()
  }

  return (
    <button onClick={handleClick} className={className}>
      {children}
    </button>
  )
}

export interface SignOutButtonProps {
  children?: ReactNode
  className?: string
  redirectTo?: string
}

/**
 * Sign Out Button - clears auth state and optionally redirects
 *
 * @example
 * ```tsx
 * import { SignOutButton } from 'oauth.do/react'
 *
 * function Header() {
 *   return <SignOutButton>Sign Out</SignOutButton>
 * }
 * ```
 */
export function SignOutButton({
  children = 'Sign Out',
  className,
  redirectTo = '/',
}: SignOutButtonProps): JSX.Element {
  const handleClick = async () => {
    // Clear local storage/cookies
    if (typeof window !== 'undefined') {
      localStorage.removeItem('oauth.do:token')
      document.cookie = 'auth=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;'
      window.location.href = redirectTo
    }
  }

  return (
    <button onClick={handleClick} className={className}>
      {children}
    </button>
  )
}

// ═══════════════════════════════════════════════════════════════════════════
// Re-exports
// ═══════════════════════════════════════════════════════════════════════════

export type { AuthToken }
