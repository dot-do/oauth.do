/**
 * Route modules for the OAuth 2.1 server
 *
 * Each module returns a Hono sub-app with related endpoints grouped together.
 * The main server.ts composes these into a single app.
 */

export { createDiscoveryRoutes } from './discovery.js'
export { createAuthorizeRoutes } from './authorize.js'
export { createTokenRoutes } from './token.js'
export { createClientRoutes } from './clients.js'
export { createDeviceRoutes } from './device.js'
export { createIntrospectRoutes } from './introspect.js'
