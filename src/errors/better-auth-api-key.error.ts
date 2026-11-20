import { AuthenticationError } from "@nestjs/authentication";

/**
 * An API key the `apiKey()` plugin refused: unknown, expired, disabled, rate
 * limited, out of requests, or owned by no user. A 401 with one generic
 * message, so the client can't tell which; the reason is logged at debug
 * level.
 */
export class BetterAuthApiKeyError extends AuthenticationError {
	constructor(challenge: string) {
		super("Invalid API key", { code: "invalid_token", challenge });
		this.name = "BetterAuthApiKeyError";
	}
}
