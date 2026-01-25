/**
 * Mock @mdxui/auth for React tests
 * This mock is needed because @mdxui/auth has broken dependencies
 */

import React from 'react'

export const IdentityProvider = ({ children }: { children: React.ReactNode }) => {
	return React.createElement(
		'div',
		{ 'data-testid': 'identity-provider' },
		React.createElement(
			'div',
			{ 'data-testid': 'authkit-provider' },
			React.createElement('div', { 'data-testid': 'workos-widgets' }, children)
		)
	)
}

export const useAuth = () => ({
	isLoading: false,
	user: null,
	role: null,
	roles: null,
	organizationId: null,
	permissions: [],
	featureFlags: [],
	impersonator: null,
	authenticationMethod: null,
	signIn: () => {},
	signUp: () => {},
	getUser: () => null,
	getAccessToken: async () => 'mock-access-token',
	signOut: () => {},
	switchToOrganization: async () => {},
	getSignInUrl: async () => 'https://login.oauth.do/sign-in',
	getSignUpUrl: async () => 'https://login.oauth.do/sign-up',
})

export const SignInButton = ({
	children,
	className,
}: {
	children?: React.ReactNode
	className?: string
}) => {
	return React.createElement('button', { className }, children ?? 'Sign In')
}

export const SignOutButton = ({
	children,
	className,
}: {
	children?: React.ReactNode
	className?: string
}) => {
	return React.createElement('button', { className }, children ?? 'Sign Out')
}

export const ApiKeys = ({ authToken }: { authToken: string }) => {
	return React.createElement('div', { 'data-testid': 'api-keys' }, `ApiKeys: ${typeof authToken}`)
}

export const UsersManagement = ({ authToken }: { authToken: string }) => {
	return React.createElement('div', { 'data-testid': 'users-management' }, `UsersManagement: ${typeof authToken}`)
}

export const UserProfile = ({ authToken }: { authToken: string }) => {
	return React.createElement('div', { 'data-testid': 'user-profile' }, `UserProfile: ${typeof authToken}`)
}

export const UserMenu = ({ className }: { className?: string }) => {
	return React.createElement('div', { 'data-testid': 'user-menu', className }, 'UserMenu')
}

export const TeamSwitcher = ({ className }: { className?: string }) => {
	return React.createElement('div', { 'data-testid': 'team-switcher', className }, 'TeamSwitcher')
}

export const OrganizationSwitcher = ({
	authToken,
	switchToOrganization,
}: {
	authToken: any
	switchToOrganization: any
}) => {
	return React.createElement('div', { 'data-testid': 'organization-switcher' }, 'OrganizationSwitcher')
}

// Type exports
export type AuthToken = string | (() => Promise<string>)

export interface AuthUser {
	id: string
	email?: string
	firstName?: string
	lastName?: string
	profilePictureUrl?: string
}

export interface Impersonator {
	email: string
	reason?: string
}

export interface IdentityProviderProps {
	children: React.ReactNode
	clientId?: string
	apiHostname?: string
}
