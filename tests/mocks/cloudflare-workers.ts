/**
 * Mock cloudflare:workers for Node.js tests
 */

export const env = {
	DO_ADMIN_TOKEN: undefined,
}

/**
 * Mock WorkerEntrypoint base class
 */
export class WorkerEntrypoint<E = unknown> {
	protected env: E

	constructor(ctx: unknown, env: E) {
		this.env = env
	}
}

/**
 * Mock DurableObject base class
 */
export class DurableObject<E = unknown> {
	protected env: E
	protected ctx: unknown

	constructor(ctx: unknown, env: E) {
		this.ctx = ctx
		this.env = env
	}
}
