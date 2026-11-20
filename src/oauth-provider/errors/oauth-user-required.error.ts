import { AuthenticationError } from "@nestjs/authentication";

/**
 * An OAuth access token with no user behind it, from the
 * `client_credentials` grant: a 403 (`user_required`), as this API
 * authenticates users.
 */
export class OAuthUserRequiredError extends AuthenticationError {
	override readonly status = 403 as const;

	constructor() {
		super("This API needs an access token issued for a user", {
			code: "user_required",
		});
		this.name = "OAuthUserRequiredError";
	}
}
