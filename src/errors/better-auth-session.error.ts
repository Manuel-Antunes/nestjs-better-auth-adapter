import { AuthenticationError } from "@nestjs/authentication";

/**
 * A Better Auth session that `BetterAuthSessionProvider.validate()` refused
 * (a subclass's own check): a 401 (`invalid_session`).
 */
export class BetterAuthSessionError extends AuthenticationError {
	constructor(description = "Session refused") {
		super(description, { code: "invalid_session" });
		this.name = "BetterAuthSessionError";
	}
}
