/**
 * oauth.do/react - React components for authentication
 *
 * Wraps @mdxui/auth with oauth.do configuration.
 * Pre-configured with oauth.do WorkOS client ID and domain.
 *
 * @packageDocumentation
 */

'use client'

import React, { createContext, useContext, type ReactNode } from 'react'

// Import from @mdxui/auth instead of direct WorkOS packages
import {
  IdentityProvider,
  useAuth as useMdxuiAuth,
  ApiKeys as MdxuiApiKeys,
  UsersManagement as MdxuiUsersManagement,
  UserProfile as MdxuiUserProfile,
  UserMenu as MdxuiUserMenu,
  TeamSwitcher as MdxuiTeamSwitcher,
  OrganizationSwitcher as MdxuiOrganizationSwitcher,
  type AuthToken,
  type AuthUser,
  type Impersonator,
  type IdentityProviderProps,
} from '@mdxui/auth'

// ===============================================================================
// oauth.do default configuration
// ===============================================================================

const OAUTH_DO_CONFIG = {
  clientId: 'client_01JQYTRXK9ZPD8JPJTKDCRB656',
  apiUrl: 'https://apis.do',
  authKitDomain: 'login.oauth.do',
}

// ===============================================================================
// Context for oauth.do-specific config
// ===============================================================================

interface OAuthDoContextValue {
  clientId: string
  apiUrl: string
  authKitDomain: string
}

const OAuthDoContext = createContext<OAuthDoContextValue>(OAUTH_DO_CONFIG)

/**
 * Hook to access oauth.do-specific configuration
 *
 * @example
 * ```tsx
 * import { useOAuthDoConfig } from 'oauth.do/react'
 *
 * function MyComponent() {
 *   const { clientId, apiUrl, authKitDomain } = useOAuthDoConfig()
 *   // Use config values...
 * }
 * ```
 */
export function useOAuthDoConfig(): OAuthDoContextValue {
  return useContext(OAuthDoContext)
}

// ===============================================================================
// Provider
// ===============================================================================

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
 * Pre-configured with oauth.do defaults:
 * - clientId: client_01JQYTRXK9ZPD8JPJTKDCRB656
 * - authKitDomain: login.oauth.do
 * - apiUrl: https://apis.do
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
 *
 * @example
 * ```tsx
 * // With custom overrides
 * <OAuthDoProvider
 *   clientId="custom-client-id"
 *   apiUrl="https://custom.api.do"
 * >
 *   {children}
 * </OAuthDoProvider>
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
      <IdentityProvider clientId={clientId} apiHostname={authKitDomain}>
        {children}
      </IdentityProvider>
    </OAuthDoContext.Provider>
  )
}

// ===============================================================================
// Re-exported Auth Types
// ===============================================================================

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
  user: AuthUser | null
  role: string | null
  roles: string[] | null
  organizationId: string | null
  permissions: string[]
  featureFlags: string[]
  impersonator: Impersonator | null
  authenticationMethod: string | null
  signIn: () => void
  signUp: () => void
  getUser: () => AuthUser | null
  getAccessToken: () => Promise<string>
  signOut: () => void
  switchToOrganization: (options: SwitchToOrganizationOptions) => Promise<void>
  getSignInUrl: () => Promise<string>
  getSignUpUrl: () => Promise<string>
}

// ===============================================================================
// Hooks
// ===============================================================================

/**
 * useAuth hook - access current user and auth state
 *
 * Re-exported from @mdxui/auth with AuthState typing.
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
  return useMdxuiAuth() as AuthState
}

// ===============================================================================
// Widgets - Re-exported from @mdxui/auth
// ===============================================================================

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
  return <MdxuiApiKeys authToken={authToken} />
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
  return <MdxuiUsersManagement authToken={authToken} />
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
  return <MdxuiUserProfile authToken={authToken} />
}

// ===============================================================================
// Login Components - oauth.do specific with URL-based redirect
// ===============================================================================

export interface SignInButtonProps {
  children?: ReactNode
  className?: string
  redirectTo?: string
}

/**
 * Sign In Button - redirects to oauth.do login
 *
 * Uses oauth.do-specific URL-based redirect for authentication.
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

// ===============================================================================
// New Components - Re-exported from @mdxui/auth
// ===============================================================================

/**
 * UserMenu - A customizable user menu component
 *
 * Re-exported from @mdxui/auth. Displays user info and provides sign-out functionality.
 *
 * @example
 * ```tsx
 * import { UserMenu } from 'oauth.do/react'
 *
 * function Header() {
 *   return (
 *     <UserMenu
 *       renderTrigger={({ user, initials }) => (
 *         <button>{user.firstName}</button>
 *       )}
 *       renderMenu={({ signOut }) => (
 *         <button onClick={signOut}>Sign Out</button>
 *       )}
 *     />
 *   )
 * }
 * ```
 */
export const UserMenu = MdxuiUserMenu

/**
 * TeamSwitcher - Organization switching component
 *
 * Re-exported from @mdxui/auth. Shows WorkOS OrganizationSwitcher widget.
 *
 * @example
 * ```tsx
 * import { TeamSwitcher } from 'oauth.do/react'
 *
 * function Sidebar() {
 *   return <TeamSwitcher className="my-team-switcher" />
 * }
 * ```
 */
export const TeamSwitcher = MdxuiTeamSwitcher

/**
 * OrganizationSwitcher - Lower-level organization switcher widget
 *
 * Re-exported from @mdxui/auth. Use with useAuth() for full control.
 *
 * @example
 * ```tsx
 * import { OrganizationSwitcher, useAuth } from 'oauth.do/react'
 *
 * function OrgSwitcher() {
 *   const { getAccessToken, switchToOrganization } = useAuth()
 *
 *   return (
 *     <OrganizationSwitcher
 *       authToken={getAccessToken}
 *       switchToOrganization={({ organizationId }) =>
 *         switchToOrganization({ organizationId })
 *       }
 *     />
 *   )
 * }
 * ```
 */
export const OrganizationSwitcher = MdxuiOrganizationSwitcher

// ===============================================================================
// Type Re-exports
// ===============================================================================

export type { AuthToken, AuthUser, Impersonator, IdentityProviderProps }

// Re-export User as alias for AuthUser for backward compatibility
export type User = AuthUser

// Re-export AuthenticationMethod type
export type AuthenticationMethod = string | null
