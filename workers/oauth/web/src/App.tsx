import React, { useEffect, useRef } from 'react'
import { Routes, Route, Link, useLocation, Navigate } from 'react-router-dom'
import { Box, Container, Flex, Heading, Text, Button, Card, Tabs, Avatar, DropdownMenu } from '@radix-ui/themes'
import { IdentityProvider, useAuth, ApiKeys, UsersManagement, UserProfile } from '@mdxui/auth'

const CLIENT_ID = 'client_01JQYTRXK9ZPD8JPJTKDCRB656'
const API_HOSTNAME = 'auth.apis.do'

function LoadingSpinner() {
  return (
    <Flex justify="center" align="center" style={{ height: 'calc(100vh - 60px)' }}>
      <Box style={{
        width: 40,
        height: 40,
        border: '3px solid var(--gray-6)',
        borderTopColor: 'var(--accent-9)',
        borderRadius: '50%',
        animation: 'spin 1s linear infinite',
      }} />
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </Flex>
  )
}

/**
 * AuthGate that automatically triggers signIn when not authenticated
 */
function AutoSignInGate({ children }: { children: React.ReactNode }) {
  const { user, isLoading, signIn } = useAuth()
  const signInCalled = useRef(false)

  useEffect(() => {
    if (!isLoading && !user && !signInCalled.current) {
      signInCalled.current = true
      signIn()
    }
  }, [isLoading, user, signIn])

  useEffect(() => {
    if (user) {
      signInCalled.current = false
    }
  }, [user])

  if (isLoading || !user) {
    return <LoadingSpinner />
  }

  return <>{children}</>
}

function Navigation() {
  const { user, isLoading, signIn, signOut } = useAuth()
  const location = useLocation()

  // Don't show nav while loading or if not logged in
  if (isLoading || !user) return null

  return (
    <Box py="4" style={{ borderBottom: '1px solid var(--gray-6)' }}>
      <Container size="3">
        <Flex justify="between" align="center">
          <Flex align="center" gap="6">
            <Link to="/">
              <Heading size="5" style={{ color: 'var(--gray-12)' }}>oauth.do</Heading>
            </Link>
            <Flex gap="4">
              <Link to="/api-keys" style={{ color: location.pathname === '/api-keys' ? 'var(--accent-11)' : 'var(--gray-11)' }}>
                <Text size="2">API Keys</Text>
              </Link>
              <Link to="/users" style={{ color: location.pathname === '/users' ? 'var(--accent-11)' : 'var(--gray-11)' }}>
                <Text size="2">Users</Text>
              </Link>
              <Link to="/profile" style={{ color: location.pathname === '/profile' ? 'var(--accent-11)' : 'var(--gray-11)' }}>
                <Text size="2">Profile</Text>
              </Link>
              <Link to="/docs" style={{ color: location.pathname === '/docs' ? 'var(--accent-11)' : 'var(--gray-11)' }}>
                <Text size="2">Docs</Text>
              </Link>
            </Flex>
          </Flex>
          <DropdownMenu.Root>
            <DropdownMenu.Trigger>
              <Button variant="ghost" style={{ cursor: 'pointer' }}>
                <Flex align="center" gap="2">
                  <Avatar
                    size="1"
                    src={user.profilePictureUrl || undefined}
                    fallback={user.firstName?.[0] || user.email?.[0] || '?'}
                  />
                  <Text size="2">{user.firstName || user.email}</Text>
                </Flex>
              </Button>
            </DropdownMenu.Trigger>
            <DropdownMenu.Content>
              <DropdownMenu.Item asChild>
                <Link to="/profile">Profile</Link>
              </DropdownMenu.Item>
              <DropdownMenu.Item asChild>
                <Link to="/api-keys">API Keys</Link>
              </DropdownMenu.Item>
              <DropdownMenu.Separator />
              <DropdownMenu.Item color="red" onClick={() => signOut()}>
                Sign Out
              </DropdownMenu.Item>
            </DropdownMenu.Content>
          </DropdownMenu.Root>
        </Flex>
      </Container>
    </Box>
  )
}


function ApiKeysPage() {
  const { getAccessToken, user } = useAuth()
  const [tokenStatus, setTokenStatus] = React.useState<string>('checking...')

  React.useEffect(() => {
    getAccessToken()
      .then(token => setTokenStatus(`Token: ${token?.substring(0, 20)}...`))
      .catch(err => setTokenStatus(`Error: ${err.message}`))
  }, [getAccessToken])

  return (
    <Container size="3" py="6">
      <Heading size="6" mb="4">API Keys</Heading>
      <Text color="gray" mb="6">
        Create and manage API keys for authenticating with apis.do services.
      </Text>
      <Text size="1" color="gray" mb="4">Debug - User: {user?.email} | {tokenStatus}</Text>
      <ApiKeys authToken={getAccessToken} />
    </Container>
  )
}

function UsersPage() {
  const { getAccessToken } = useAuth()

  return (
    <Container size="3" py="6">
      <Heading size="6" mb="4">Users</Heading>
      <Text color="gray" mb="6">
        Invite team members and manage user access.
      </Text>
      <UsersManagement authToken={getAccessToken} />
    </Container>
  )
}

function ProfilePage() {
  const { getAccessToken } = useAuth()

  return (
    <Container size="3" py="6">
      <Heading size="6" mb="4">Profile</Heading>
      <UserProfile authToken={getAccessToken} />
    </Container>
  )
}

function DocsPage() {
  return (
    <Container size="3" py="6">
      <Heading size="6" mb="4">Documentation</Heading>
      <Tabs.Root defaultValue="react">
        <Tabs.List>
          <Tabs.Trigger value="react">React</Tabs.Trigger>
          <Tabs.Trigger value="node">Node.js</Tabs.Trigger>
          <Tabs.Trigger value="cli">CLI</Tabs.Trigger>
        </Tabs.List>
        <Box pt="4">
          <Tabs.Content value="react">
            <Card>
              <Flex direction="column" gap="4">
                <Heading size="4">React Components</Heading>
                <Text as="p">Install the oauth.do package:</Text>
                <Box p="3" style={{ background: 'var(--gray-3)', borderRadius: 'var(--radius-2)', fontFamily: 'monospace' }}>
                  npm install oauth.do
                </Box>
              </Flex>
            </Card>
          </Tabs.Content>
          <Tabs.Content value="node">
            <Card>
              <Flex direction="column" gap="4">
                <Heading size="4">Node.js SDK</Heading>
                <Box p="3" style={{ background: 'var(--gray-3)', borderRadius: 'var(--radius-2)', fontFamily: 'monospace', whiteSpace: 'pre' }}>
{`import { ensureLoggedIn } from 'oauth.do'
const { token } = await ensureLoggedIn()`}
                </Box>
              </Flex>
            </Card>
          </Tabs.Content>
          <Tabs.Content value="cli">
            <Card>
              <Flex direction="column" gap="4">
                <Heading size="4">CLI Usage</Heading>
                <Box p="3" style={{ background: 'var(--gray-3)', borderRadius: 'var(--radius-2)', fontFamily: 'monospace' }}>
                  npx oauth.do login
                </Box>
              </Flex>
            </Card>
          </Tabs.Content>
        </Box>
      </Tabs.Root>
    </Container>
  )
}

export default function App() {
  return (
    <IdentityProvider clientId={CLIENT_ID} apiHostname={API_HOSTNAME} redirectUri="https://oauth.do/callback">
      <Box style={{ minHeight: '100vh', background: 'var(--gray-1)' }}>
        <Navigation />
        <AutoSignInGate>
          <Routes>
            <Route path="/" element={<Navigate to="/api-keys" replace />} />
            <Route path="/api-keys" element={<ApiKeysPage />} />
            <Route path="/users" element={<UsersPage />} />
            <Route path="/profile" element={<ProfilePage />} />
            <Route path="/docs" element={<DocsPage />} />
            <Route path="*" element={<Navigate to="/api-keys" replace />} />
          </Routes>
        </AutoSignInGate>
      </Box>
    </IdentityProvider>
  )
}
