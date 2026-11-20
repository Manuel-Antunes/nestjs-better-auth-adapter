/**
 * The app's configuration can't work with Better Auth as set up: a missing
 * plugin, an option Better Auth owns, a handler that can't plug itself in.
 * Thrown at startup (or, for a `nestPasswordHasher()` or `fromNestHandler`
 * placeholder, on first use), never because of a request.
 */
export class BetterAuthConfigurationError extends Error {
	constructor(message: string, options?: ErrorOptions) {
		super(message, options);
		this.name = "BetterAuthConfigurationError";
	}
}
