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
  UsersManagement as WorkOSUsersManagement,
  UserProfile as WorkOSUserProfile
} from '@workos-inc/widgets'
import {
  AuthKitProvider as WorkOSAuthKitProvider,
  useAuth as useWorkOSAuth,
  type Impersonator,
  type User,
  type AuthenticationMethod
} from '@workos-inc/authkit-react'

/**
 * Auth token can be a string or a function that returns a Promise<string>
 */
export type AuthToken = string | (() => Promise<string>)
import React, { createContext, useContext, type ReactNode } from 'react'

// ═══════════════════════════════════════════════════════════════════════════
// Auth Types (re-exported from authkit-react context)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Options for switching organization
 */
export interface SwitchToOrganizationOptions {
  organizationId: string
  signInOpts?: {
    screenHint?: 'sign-in' | 'sign-up'
    loginHint?: string
  }
}

/**
 * Auth state and methods returned by useAuth hook
 */
export interface AuthState {
  isLoading: boolean
  user: User | null
  role: string | null
  roles: string[] | null
  organizationId: string | null
  permissions: string[]
  featureFlags: string[]
  impersonator: Impersonator | null
  authenticationMethod: AuthenticationMethod | null
  signIn: () => void
  signUp: () => void
  getUser: () => User | null
  getAccessToken: () => Promise<string>
  signOut: () => void
  switchToOrganization: (options: SwitchToOrganizationOptions) => Promise<void>
  getSignInUrl: () => Promise<string>
  getSignUpUrl: () => Promise<string>
}

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
}: OAuthDoProviderProps): JSX.Element {
  const config = { clientId, apiUrl, authKitDomain }

  return (
    <OAuthDoContext.Provider value={config}>
      <WorkOSAuthKitProvider clientId={clientId}>
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
export function useAuth(): AuthState {
  return useWorkOSAuth() as AuthState
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

export interface UsersManagementProps {
  /** Auth token for the widget */
  authToken: AuthToken
}

/**
 * Users Management Widget - invite, remove, and manage users
 *
 * @example
 * ```tsx
 * import { UsersManagement, useAuth } from 'oauth.do/react'
 *
 * function UsersPage() {
 *   const { user, getAccessToken } = useAuth()
 *   if (!user) return <p>Please sign in</p>
 *
 *   return <UsersManagement authToken={getAccessToken} />
 * }
 * ```
 */
export function UsersManagement({ authToken }: UsersManagementProps): JSX.Element {
  return <WorkOSUsersManagement authToken={authToken} />
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
  const { signOut } = useAuth()

  const handleClick = () => {
    signOut()
    // Redirect after signOut if a custom redirectTo is provided
    if (redirectTo !== '/' && typeof window !== 'undefined') {
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

export type { User, Impersonator, AuthenticationMethod }
