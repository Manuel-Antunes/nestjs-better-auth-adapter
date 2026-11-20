/**
 * A call to a step of `@nestjs/authentication`'s own flows that Better Auth
 * replaces in this app: a store or handler method Nest's services would
 * call, or a provider method Better Auth's endpoints stand for. Use Better
 * Auth's endpoints, or `BetterAuthService.api`.
 */
export class OwnedByBetterAuthError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "OwnedByBetterAuthError";
	}

	/** A Nest-only method of a Better Auth handler. */
	static handlerStep(method: string, step: string): OwnedByBetterAuthError {
		return new OwnedByBetterAuthError(
			`${method}() is part of Nest's own flow, which Better Auth replaces here: ${step}. A Better Auth handler only delivers Better Auth's links, through send().`,
		);
	}

	/** A method of one of `@nestjs/authentication`'s stores for what Better Auth keeps. */
	static store(
		store: string,
		method: string,
		owns: string,
	): OwnedByBetterAuthError {
		return new OwnedByBetterAuthError(
			`${store}.${method}(): Better Auth owns ${owns} in this app, so @nestjs/authentication's own flows for them don't run. Use Better Auth's endpoints, or BetterAuthService.api.`,
		);
	}
}
