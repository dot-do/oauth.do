/**
 * Type declarations for @mdxui/auth
 *
 * This stub file allows TypeScript to compile when @mdxui/auth is not installed.
 * The actual implementation is provided by the peer dependency at runtime.
 */

declare module '@mdxui/auth' {
  import type { ReactNode, ButtonHTMLAttributes } from 'react'

  // ============================================================================
  // Auth Types
  // ============================================================================

  /**
   * Authenticated user information
   */
  export interface AuthUser {
    id: string
    email: string
    firstName?: string | null
    lastName?: string | null
    profilePictureUrl?: string | null
    createdAt?: string
    updatedAt?: string
    emailVerified?: boolean
    [key: string]: unknown
  }

  /**
   * Impersonator information when an admin is impersonating a user
   */
  export interface Impersonator {
    email: string
    reason?: string | null
  }

  /**
   * Auth token can be a string or a function that returns a Promise<string>
   */
  export type AuthToken = string | (() => Promise<string>)

  /**
   * Organization information
   */
  export interface AuthOrganization {
    id: string
    name: string
    slug?: string
  }

  /**
   * Session information
   */
  export interface AuthSession {
    id: string
    userId: string
    createdAt: string
    expiresAt: string
    ipAddress?: string
    userAgent?: string
  }

  // ============================================================================
  // Provider Types
  // ============================================================================

  export interface IdentityProviderProps {
    /** WorkOS client ID */
    clientId: string
    /** Optional API hostname override */
    apiHostname?: string
    /** Enable dev mode for local development */
    devMode?: boolean
    /** Redirect URI after authentication */
    redirectUri?: string
    /** Callback after redirect */
    onRedirectCallback?: () => void
    /** Children to render */
    children: ReactNode
  }

  export interface AuthGateProps {
    children: ReactNode
    required?: boolean
    loadingComponent?: ReactNode
    landingComponent?: ReactNode
    onUnauthenticated?: 'landing' | 'redirect' | 'allow'
    redirectUrl?: string
  }

  export interface WidgetsProviderProps {
    children: ReactNode
    appearance?: 'light' | 'dark' | 'inherit'
    radius?: 'none' | 'small' | 'medium' | 'large' | 'full'
    scaling?: '90%' | '95%' | '100%' | '105%' | '110%'
  }

  // ============================================================================
  // Component Props Types
  // ============================================================================

  export interface BaseWidgetProps {
    authToken: AuthToken
    className?: string
  }

  export interface OrganizationWidgetProps extends BaseWidgetProps {
    organizationId?: string
  }

  export interface SignInButtonProps
    extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'onClick'> {
    children?: ReactNode
    onSignIn?: () => void
  }

  export interface SignOutButtonProps
    extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'onClick'> {
    children?: ReactNode
    onSignOut?: () => void
  }

  export interface UserMenuProps {
    renderTrigger?: (props: {
      user: AuthUser
      displayName: string
      initials: string
    }) => ReactNode
    renderMenu?: (props: {
      user: AuthUser
      displayName: string
      initials: string
      signOut: () => void
    }) => ReactNode
    className?: string
  }

  export interface TeamSwitcherProps {
    renderWrapper?: (children: ReactNode) => ReactNode
    renderNoOrganization?: () => ReactNode
    className?: string
  }

  export interface OrganizationSwitcherProps {
    authToken: () => Promise<string>
    switchToOrganization: (args: { organizationId: string }) => void | Promise<void>
    variant?: 'ghost' | 'outline'
    organizationLabel?: string | null
    truncateBehavior?: 'right' | 'middle'
    className?: string
  }

  export interface UseWidgetTokenOptions {
    widget: string
    organizationId?: string
    endpoint?: string
  }

  export interface UseWidgetTokenResult {
    token: string | null
    loading: boolean
    error: string | null
    refetch: () => Promise<void>
  }

  // ============================================================================
  // Auth Hook Return Type
  // ============================================================================

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
    switchToOrganization: (options: { organizationId: string }) => Promise<void>
    getSignInUrl: () => Promise<string>
    getSignUpUrl: () => Promise<string>
  }

  // ============================================================================
  // Providers
  // ============================================================================

  export function IdentityProvider(props: IdentityProviderProps): JSX.Element
  export function IdentityProviderMinimal(props: IdentityProviderProps): JSX.Element
  export function AuthGate(props: AuthGateProps): JSX.Element
  export function WidgetsProvider(props: WidgetsProviderProps): JSX.Element
  export function useThemeDetection(): 'light' | 'dark'

  // ============================================================================
  // Hooks
  // ============================================================================

  export function useAuth(): AuthState
  export function useWidgetToken(options: UseWidgetTokenOptions): UseWidgetTokenResult

  // ============================================================================
  // Components
  // ============================================================================

  export function SignInButton(props: SignInButtonProps): JSX.Element
  export function SignOutButton(props: SignOutButtonProps): JSX.Element
  export function UserMenu(props: UserMenuProps): JSX.Element | null
  export function TeamSwitcher(props: TeamSwitcherProps): JSX.Element | null

  // ============================================================================
  // Widgets
  // ============================================================================

  export function ApiKeys(props: BaseWidgetProps): JSX.Element
  export function UsersManagement(props: BaseWidgetProps): JSX.Element
  export function UserProfile(props: BaseWidgetProps): JSX.Element
  export function UserSecurity(props: BaseWidgetProps): JSX.Element
  export function UserSessions(props: BaseWidgetProps): JSX.Element
  export function Pipes(props: BaseWidgetProps): JSX.Element
  export function OrganizationSwitcher(props: OrganizationSwitcherProps): JSX.Element
}
