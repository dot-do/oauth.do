/**
 * Safe environment variable access (works in Node, browser, and Workers)
 *
 * Checks in order:
 * 1. globalThis (Cloudflare Workers legacy)
 * 2. process.env (Node.js)
 *
 * @param key - The environment variable key to look up
 * @returns The environment variable value or undefined if not found
 */
export function getEnv(key: string): string | undefined {
	// Check globalThis first (Workers)
	if ((globalThis as any)[key]) return (globalThis as any)[key]
	// Check process.env (Node.js)
	if (typeof process !== 'undefined' && process.env?.[key]) return process.env[key]
	return undefined
}
