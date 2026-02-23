/**
 * Tests for oauth.do React components
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import React from 'react'

// Mock @mdxui/auth
const mockSignIn = vi.fn()
const mockSignUp = vi.fn()
const mockSignOut = vi.fn()
const mockGetAccessToken = vi.fn().mockResolvedValue('mock-access-token')
const mockGetUser = vi.fn().mockReturnValue(null)
const mockSwitchToOrganization = vi.fn()
const mockGetSignInUrl = vi.fn().mockResolvedValue('https://login.oauth.do/sign-in')
const mockGetSignUpUrl = vi.fn().mockResolvedValue('https://login.oauth.do/sign-up')

const mockUseAuth = vi.fn().mockReturnValue({
	isLoading: false,
	user: null,
	role: null,
	roles: null,
	organizationId: null,
	permissions: [],
	featureFlags: [],
	impersonator: null,
	authenticationMethod: null,
	signIn: mockSignIn,
	signUp: mockSignUp,
	getUser: mockGetUser,
	getAccessToken: mockGetAccessToken,
	signOut: mockSignOut,
	switchToOrganization: mockSwitchToOrganization,
	getSignInUrl: mockGetSignInUrl,
	getSignUpUrl: mockGetSignUpUrl,
})

vi.mock('@mdxui/auth', () => ({
	IdentityProvider: ({ children }: { children: React.ReactNode }) => (
		<div data-testid="identity-provider">
			<div data-testid="authkit-provider">
				<div data-testid="workos-widgets">{children}</div>
			</div>
		</div>
	),
	useAuth: () => mockUseAuth(),
	SignInButton: ({ children, className }: { children?: React.ReactNode; className?: string }) => (
		<button className={className}>{children ?? 'Sign In'}</button>
	),
	SignOutButton: ({ children, className }: { children?: React.ReactNode; className?: string }) => (
		<button className={className}>{children ?? 'Sign Out'}</button>
	),
	ApiKeys: ({ authToken }: { authToken: string }) => (
		<div data-testid="api-keys">ApiKeys: {typeof authToken}</div>
	),
	UsersManagement: ({ authToken }: { authToken: string }) => (
		<div data-testid="users-management">UsersManagement: {typeof authToken}</div>
	),
	UserProfile: ({ authToken }: { authToken: string }) => (
		<div data-testid="user-profile">UserProfile: {typeof authToken}</div>
	),
	UserMenu: ({ className }: { className?: string }) => (
		<div data-testid="user-menu" className={className}>UserMenu</div>
	),
	TeamSwitcher: ({ className }: { className?: string }) => (
		<div data-testid="team-switcher" className={className}>TeamSwitcher</div>
	),
	OrganizationSwitcher: ({ authToken, switchToOrganization }: { authToken: any; switchToOrganization: any }) => (
		<div data-testid="organization-switcher">OrganizationSwitcher</div>
	),
}))

// Import after mocks are set up
import {
	OAuthDoProvider,
	useOAuthDoConfig,
	useAuth,
	SignInButton,
	SignOutButton,
	ApiKeys,
	UsersManagement,
	UserProfile,
	UserMenu,
	TeamSwitcher,
	OrganizationSwitcher,
} from '../src/react.js'

// Helper component to test useOAuthDoConfig hook
function ConfigDisplay() {
	const config = useOAuthDoConfig()
	return (
		<div>
			<span data-testid="client-id">{config.clientId}</span>
			<span data-testid="api-url">{config.apiUrl}</span>
			<span data-testid="auth-domain">{config.authKitDomain}</span>
		</div>
	)
}

// Helper component to test useAuth hook
function AuthDisplay() {
	const auth = useAuth()
	return (
		<div>
			<span data-testid="is-loading">{String(auth.isLoading)}</span>
			<span data-testid="user">{auth.user ? auth.user.email : 'null'}</span>
		</div>
	)
}

describe('React Components', () => {
	beforeEach(() => {
		vi.clearAllMocks()
		// Reset location.href mock
		Object.defineProperty(window, 'location', {
			value: { href: 'http://localhost:3000' },
			writable: true,
		})
	})

	describe('OAuthDoProvider', () => {
		it('renders children', () => {
			render(
				<OAuthDoProvider>
					<div data-testid="child">Hello</div>
				</OAuthDoProvider>
			)

			expect(screen.getByTestId('child')).toHaveTextContent('Hello')
		})

		it('provides context with default config', () => {
			render(
				<OAuthDoProvider>
					<ConfigDisplay />
				</OAuthDoProvider>
			)

			expect(screen.getByTestId('client-id')).toHaveTextContent('client_01JQYTRXK9ZPD8JPJTKDCRB656')
			expect(screen.getByTestId('api-url')).toHaveTextContent('https://id.org.ai')
			expect(screen.getByTestId('auth-domain')).toHaveTextContent('login.oauth.do')
		})

		it('allows custom clientId override', () => {
			render(
				<OAuthDoProvider clientId="custom-client-id">
					<ConfigDisplay />
				</OAuthDoProvider>
			)

			expect(screen.getByTestId('client-id')).toHaveTextContent('custom-client-id')
		})

		it('allows custom apiUrl override', () => {
			render(
				<OAuthDoProvider apiUrl="https://custom.apis.do">
					<ConfigDisplay />
				</OAuthDoProvider>
			)

			expect(screen.getByTestId('api-url')).toHaveTextContent('https://custom.apis.do')
		})

		it('allows custom authKitDomain override', () => {
			render(
				<OAuthDoProvider authKitDomain="custom.oauth.do">
					<ConfigDisplay />
				</OAuthDoProvider>
			)

			expect(screen.getByTestId('auth-domain')).toHaveTextContent('custom.oauth.do')
		})

		it('wraps children with IdentityProvider from @mdxui/auth', () => {
			render(
				<OAuthDoProvider>
					<div>Content</div>
				</OAuthDoProvider>
			)

			expect(screen.getByTestId('identity-provider')).toBeInTheDocument()
		})

		it('wraps children with AuthKitProvider (via IdentityProvider)', () => {
			render(
				<OAuthDoProvider>
					<div>Content</div>
				</OAuthDoProvider>
			)

			expect(screen.getByTestId('authkit-provider')).toBeInTheDocument()
		})

		it('wraps children with WorkOsWidgets (via IdentityProvider)', () => {
			render(
				<OAuthDoProvider>
					<div>Content</div>
				</OAuthDoProvider>
			)

			expect(screen.getByTestId('workos-widgets')).toBeInTheDocument()
		})
	})

	describe('useOAuthDoConfig hook', () => {
		it('returns default config values', () => {
			render(
				<OAuthDoProvider>
					<ConfigDisplay />
				</OAuthDoProvider>
			)

			expect(screen.getByTestId('client-id')).toHaveTextContent('client_01JQYTRXK9ZPD8JPJTKDCRB656')
			expect(screen.getByTestId('api-url')).toHaveTextContent('https://id.org.ai')
			expect(screen.getByTestId('auth-domain')).toHaveTextContent('login.oauth.do')
		})

		it('returns overridden values from provider', () => {
			render(
				<OAuthDoProvider
					clientId="overridden-client"
					apiUrl="https://overridden.apis.do"
					authKitDomain="overridden.oauth.do"
				>
					<ConfigDisplay />
				</OAuthDoProvider>
			)

			expect(screen.getByTestId('client-id')).toHaveTextContent('overridden-client')
			expect(screen.getByTestId('api-url')).toHaveTextContent('https://overridden.apis.do')
			expect(screen.getByTestId('auth-domain')).toHaveTextContent('overridden.oauth.do')
		})
	})

	describe('useAuth hook', () => {
		it('returns auth state from @mdxui/auth', () => {
			render(
				<OAuthDoProvider>
					<AuthDisplay />
				</OAuthDoProvider>
			)

			expect(screen.getByTestId('is-loading')).toHaveTextContent('false')
			expect(screen.getByTestId('user')).toHaveTextContent('null')
		})

		it('returns user when authenticated', () => {
			mockUseAuth.mockReturnValueOnce({
				isLoading: false,
				user: { email: 'test@example.com' },
				role: 'admin',
				roles: ['admin'],
				organizationId: 'org_123',
				permissions: ['read', 'write'],
				featureFlags: ['feature_x'],
				impersonator: null,
				authenticationMethod: 'password',
				signIn: mockSignIn,
				signUp: mockSignUp,
				getUser: mockGetUser,
				getAccessToken: mockGetAccessToken,
				signOut: mockSignOut,
				switchToOrganization: mockSwitchToOrganization,
				getSignInUrl: mockGetSignInUrl,
				getSignUpUrl: mockGetSignUpUrl,
			})

			render(
				<OAuthDoProvider>
					<AuthDisplay />
				</OAuthDoProvider>
			)

			expect(screen.getByTestId('user')).toHaveTextContent('test@example.com')
		})

		it('returns loading state', () => {
			mockUseAuth.mockReturnValueOnce({
				isLoading: true,
				user: null,
				role: null,
				roles: null,
				organizationId: null,
				permissions: [],
				featureFlags: [],
				impersonator: null,
				authenticationMethod: null,
				signIn: mockSignIn,
				signUp: mockSignUp,
				getUser: mockGetUser,
				getAccessToken: mockGetAccessToken,
				signOut: mockSignOut,
				switchToOrganization: mockSwitchToOrganization,
				getSignInUrl: mockGetSignInUrl,
				getSignUpUrl: mockGetSignUpUrl,
			})

			render(
				<OAuthDoProvider>
					<AuthDisplay />
				</OAuthDoProvider>
			)

			expect(screen.getByTestId('is-loading')).toHaveTextContent('true')
		})
	})

	describe('SignInButton', () => {
		it('renders with default text', () => {
			render(
				<OAuthDoProvider>
					<SignInButton />
				</OAuthDoProvider>
			)

			expect(screen.getByRole('button')).toHaveTextContent('Sign In')
		})

		it('renders with custom children', () => {
			render(
				<OAuthDoProvider>
					<SignInButton>Custom Sign In Text</SignInButton>
				</OAuthDoProvider>
			)

			expect(screen.getByRole('button')).toHaveTextContent('Custom Sign In Text')
		})

		it('applies className prop', () => {
			render(
				<OAuthDoProvider>
					<SignInButton className="custom-class">Sign In</SignInButton>
				</OAuthDoProvider>
			)

			expect(screen.getByRole('button')).toHaveClass('custom-class')
		})

		it('redirects to login URL on click', () => {
			render(
				<OAuthDoProvider>
					<SignInButton />
				</OAuthDoProvider>
			)

			fireEvent.click(screen.getByRole('button'))

			expect(window.location.href).toContain('https://login.oauth.do')
			expect(window.location.href).toContain('client_id=client_01JQYTRXK9ZPD8JPJTKDCRB656')
			expect(window.location.href).toContain('response_type=code')
		})

		it('includes redirect_uri in login URL', () => {
			Object.defineProperty(window, 'location', {
				value: { href: 'http://localhost:3000/dashboard' },
				writable: true,
			})

			render(
				<OAuthDoProvider>
					<SignInButton />
				</OAuthDoProvider>
			)

			fireEvent.click(screen.getByRole('button'))

			expect(window.location.href).toContain('redirect_uri=')
		})

		it('uses custom redirectTo prop', () => {
			render(
				<OAuthDoProvider>
					<SignInButton redirectTo="https://example.com/callback" />
				</OAuthDoProvider>
			)

			fireEvent.click(screen.getByRole('button'))

			expect(window.location.href).toContain('redirect_uri=https%3A%2F%2Fexample.com%2Fcallback')
		})

		it('uses custom clientId from provider', () => {
			render(
				<OAuthDoProvider clientId="custom-client">
					<SignInButton />
				</OAuthDoProvider>
			)

			fireEvent.click(screen.getByRole('button'))

			expect(window.location.href).toContain('client_id=custom-client')
		})
	})

	describe('SignOutButton', () => {
		it('renders with default text', () => {
			render(
				<OAuthDoProvider>
					<SignOutButton />
				</OAuthDoProvider>
			)

			expect(screen.getByRole('button')).toHaveTextContent('Sign Out')
		})

		it('renders with custom children', () => {
			render(
				<OAuthDoProvider>
					<SignOutButton>Custom Sign Out Text</SignOutButton>
				</OAuthDoProvider>
			)

			expect(screen.getByRole('button')).toHaveTextContent('Custom Sign Out Text')
		})

		it('applies className prop', () => {
			render(
				<OAuthDoProvider>
					<SignOutButton className="logout-button">Sign Out</SignOutButton>
				</OAuthDoProvider>
			)

			expect(screen.getByRole('button')).toHaveClass('logout-button')
		})

		it('calls signOut on click', () => {
			render(
				<OAuthDoProvider>
					<SignOutButton />
				</OAuthDoProvider>
			)

			fireEvent.click(screen.getByRole('button'))

			expect(mockSignOut).toHaveBeenCalled()
		})

		it('redirects to custom redirectTo after signOut', () => {
			Object.defineProperty(window, 'location', {
				value: { href: 'http://localhost:3000/dashboard' },
				writable: true,
			})

			render(
				<OAuthDoProvider>
					<SignOutButton redirectTo="https://example.com/goodbye" />
				</OAuthDoProvider>
			)

			fireEvent.click(screen.getByRole('button'))

			expect(mockSignOut).toHaveBeenCalled()
			expect(window.location.href).toBe('https://example.com/goodbye')
		})

		it('does not redirect for default redirectTo', () => {
			const originalHref = 'http://localhost:3000/dashboard'
			Object.defineProperty(window, 'location', {
				value: { href: originalHref },
				writable: true,
			})

			render(
				<OAuthDoProvider>
					<SignOutButton />
				</OAuthDoProvider>
			)

			fireEvent.click(screen.getByRole('button'))

			expect(mockSignOut).toHaveBeenCalled()
			// Default redirectTo is '/', so no redirect happens
			expect(window.location.href).toBe(originalHref)
		})
	})

	describe('Widget Components', () => {
		it('renders ApiKeys widget with authToken', () => {
			render(
				<OAuthDoProvider>
					<ApiKeys authToken="test-token" />
				</OAuthDoProvider>
			)

			expect(screen.getByTestId('api-keys')).toBeInTheDocument()
		})

		it('renders UsersManagement widget with authToken', () => {
			render(
				<OAuthDoProvider>
					<UsersManagement authToken="test-token" />
				</OAuthDoProvider>
			)

			expect(screen.getByTestId('users-management')).toBeInTheDocument()
		})

		it('renders UserProfile widget with authToken', () => {
			render(
				<OAuthDoProvider>
					<UserProfile authToken="test-token" />
				</OAuthDoProvider>
			)

			expect(screen.getByTestId('user-profile')).toBeInTheDocument()
		})
	})

	describe('New Components from @mdxui/auth', () => {
		it('exports UserMenu component', () => {
			render(
				<OAuthDoProvider>
					<UserMenu />
				</OAuthDoProvider>
			)

			expect(screen.getByTestId('user-menu')).toBeInTheDocument()
		})

		it('exports TeamSwitcher component', () => {
			render(
				<OAuthDoProvider>
					<TeamSwitcher />
				</OAuthDoProvider>
			)

			expect(screen.getByTestId('team-switcher')).toBeInTheDocument()
		})

		it('exports OrganizationSwitcher component', () => {
			render(
				<OAuthDoProvider>
					<OrganizationSwitcher
						authToken={mockGetAccessToken}
						switchToOrganization={mockSwitchToOrganization}
					/>
				</OAuthDoProvider>
			)

			expect(screen.getByTestId('organization-switcher')).toBeInTheDocument()
		})
	})
})
