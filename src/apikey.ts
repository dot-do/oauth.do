/**
 * API Key management via WorkOS
 *
 * Create, rotate, and delete API keys
 */

import { getConfig } from './config.js'

export interface ApiKey {
  id: string
  key: string
  name: string
  createdAt: string
  expiresAt?: string
}

export interface CreateApiKeyOptions {
  name: string
  expiresIn?: string // e.g., '30d', '1y', 'never'
  scopes?: string[]
}

export interface RotateApiKeyOptions {
  expiresIn?: string
}

/**
 * Create a new API key
 */
export async function createApiKey(
  options: CreateApiKeyOptions,
  token?: string
): Promise<ApiKey> {
  const config = getConfig()
  const authToken = token || process.env.DO_TOKEN

  if (!authToken) {
    throw new Error('Authentication required to create API key')
  }

  const response = await config.fetch(`${config.apiUrl}/api-keys`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${authToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(options),
  })

  if (!response.ok) {
    const error = await response.text()
    throw new Error(`Failed to create API key: ${error}`)
  }

  return response.json()
}

/**
 * List all API keys for the current user
 */
export async function listApiKeys(token?: string): Promise<ApiKey[]> {
  const config = getConfig()
  const authToken = token || process.env.DO_TOKEN

  if (!authToken) {
    throw new Error('Authentication required to list API keys')
  }

  const response = await config.fetch(`${config.apiUrl}/api-keys`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${authToken}`,
      'Content-Type': 'application/json',
    },
  })

  if (!response.ok) {
    const error = await response.text()
    throw new Error(`Failed to list API keys: ${error}`)
  }

  return response.json()
}

/**
 * Get a specific API key by ID
 */
export async function getApiKey(id: string, token?: string): Promise<ApiKey> {
  const config = getConfig()
  const authToken = token || process.env.DO_TOKEN

  if (!authToken) {
    throw new Error('Authentication required to get API key')
  }

  const response = await config.fetch(`${config.apiUrl}/api-keys/${id}`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${authToken}`,
      'Content-Type': 'application/json',
    },
  })

  if (!response.ok) {
    const error = await response.text()
    throw new Error(`Failed to get API key: ${error}`)
  }

  return response.json()
}

/**
 * Rotate an API key (creates new key, invalidates old)
 */
export async function rotateApiKey(
  id: string,
  options?: RotateApiKeyOptions,
  token?: string
): Promise<ApiKey> {
  const config = getConfig()
  const authToken = token || process.env.DO_TOKEN

  if (!authToken) {
    throw new Error('Authentication required to rotate API key')
  }

  const response = await config.fetch(`${config.apiUrl}/api-keys/${id}/rotate`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${authToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(options || {}),
  })

  if (!response.ok) {
    const error = await response.text()
    throw new Error(`Failed to rotate API key: ${error}`)
  }

  return response.json()
}

/**
 * Delete an API key
 */
export async function deleteApiKey(id: string, token?: string): Promise<void> {
  const config = getConfig()
  const authToken = token || process.env.DO_TOKEN

  if (!authToken) {
    throw new Error('Authentication required to delete API key')
  }

  const response = await config.fetch(`${config.apiUrl}/api-keys/${id}`, {
    method: 'DELETE',
    headers: {
      'Authorization': `Bearer ${authToken}`,
      'Content-Type': 'application/json',
    },
  })

  if (!response.ok) {
    const error = await response.text()
    throw new Error(`Failed to delete API key: ${error}`)
  }
}
