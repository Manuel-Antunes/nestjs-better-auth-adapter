import { AuthenticationError } from "@nestjs/authentication";

/**
 * An OAuth access token on a route without `@OAuthScopes.require()` or `.any()`
 * (see `BetterAuthOAuthProvider.scopesFor()`): a 403
 * (`access_token_not_accepted`). The token is valid, but stands for what a
 * user granted another app, not for their session; asking for more scopes
 * wouldn't help, so no challenge goes with it.
 */
export class OAuthAccessTokenNotAcceptedError extends AuthenticationError {
	override readonly status = 403 as const;

	constructor() {
		super("This route does not accept OAuth access tokens", {
			code: "access_token_not_accepted",
		});
		this.name = "OAuthAccessTokenNotAcceptedError";
	}
}
