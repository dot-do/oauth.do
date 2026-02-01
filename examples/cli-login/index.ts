/**
 * CLI Login Example
 *
 * Demonstrates using oauth.do for CLI authentication with device flow.
 * The ensureLoggedIn() function handles:
 * - Checking for existing valid tokens
 * - Automatic token refresh
 * - Device flow login with browser auto-launch
 */

import { ensureLoggedIn, getUser, configure } from 'oauth.do/node'

// Optional: Configure oauth.do settings
configure({
  // storagePath: '~/.my-cli/tokens.json', // Custom token storage path
})

async function main() {
  console.log('CLI Login Example\n')

  // ensureLoggedIn() returns a valid token, handling:
  // - Returning cached token if valid
  // - Refreshing token if expired but refresh token available
  // - Starting device flow login if no valid token
  const { token, isNewLogin } = await ensureLoggedIn({
    openBrowser: true, // Auto-open browser for login
    print: console.log, // Custom output function
  })

  if (isNewLogin) {
    console.log('Successfully logged in!')
  } else {
    console.log('Using existing session')
  }

  // Fetch user info using the token
  const { user } = await getUser(token)

  if (user) {
    console.log('\nUser Info:')
    console.log(`  ID: ${user.id}`)
    console.log(`  Email: ${user.email || 'N/A'}`)
    console.log(`  Name: ${user.name || 'N/A'}`)
  }

  // Use the token for API requests
  console.log('\nMaking authenticated API request...')
  const response = await fetch('https://apis.do/user', {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  })

  if (response.ok) {
    const data = await response.json()
    console.log('API Response:', JSON.stringify(data, null, 2))
  }
}

main().catch(console.error)
