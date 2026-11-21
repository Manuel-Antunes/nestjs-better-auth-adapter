import { AuthenticationError } from "@nestjs/authentication";

/**
 * A valid OAuth access token that lacks scopes the route requires
 * (`@OAuthScopes.require()`): a 403 with RFC 6750's `insufficient_scope` challenge
 * naming them, so the client can ask the user for them. `scopes` lists them,
 * and the body's `details.scope` too, for transports without headers.
 */
export class OAuthInsufficientScopeError extends AuthenticationError {
	override readonly status = 403 as const;
	/** The scopes the token lacks. */
	readonly scopes: string[];

	constructor(description: string, scopes: string[], challenge?: string) {
		super(description, {
			code: "insufficient_scope",
			challenge,
			...(scopes.length > 0 && { details: { scope: scopes.join(" ") } }),
		});
		this.name = "OAuthInsufficientScopeError";
		this.scopes = scopes;
	}
}
