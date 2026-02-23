/**
 * @dotdo/oauth - OAuth 2.1 Server for MCP
 *
 * Re-exports OAuth 2.1 core from id.org.ai/oauth.
 * Adds .do-platform-specific storage backends.
 *
 * @packageDocumentation
 */

// Re-export ALL OAuth core from id.org.ai
export * from 'id.org.ai/oauth'

// .do-specific storage backends
export { DOSQLiteStorage } from './storage-do.js'
export type { SqlStorage, SqlStorageResult, SerializedSigningKeyRow } from './storage-do.js'
export { CollectionsOAuthStorage } from './storage-collections.js'
