import { JwtError } from "@nestjs/authentication";

/**
 * A Bearer JWT that looks like one of the `jwt()` plugin's but didn't
 * verify: a 401 with RFC 6750's `invalid_token` challenge. A `JwtError`, so
 * code that handles Nest's own JWT failures handles it too.
 */
export class BetterAuthJwtError extends JwtError {
	override readonly code = "invalid_token";
	override readonly challenge: string;

	constructor(description: string, realm = "api") {
		super(description);
		this.name = "BetterAuthJwtError";
		this.challenge = `Bearer realm="${realm}", error="invalid_token", error_description="${description}"`;
	}
}
