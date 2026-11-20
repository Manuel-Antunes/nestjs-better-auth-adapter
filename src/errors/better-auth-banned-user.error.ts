import { AuthenticationError } from "@nestjs/authentication";

/**
 * A user the `admin()` plugin banned (`banned`, until `banExpires` if set):
 * a 403 (`banned_user`), whatever credential they presented. Better Auth
 * refuses them new sessions and revokes the ones they had; this keeps their
 * JWTs, API keys and OAuth access tokens out too.
 */
export class BetterAuthBannedUserError extends AuthenticationError {
	override readonly status = 403 as const;

	constructor() {
		super("This user is banned", { code: "banned_user" });
		this.name = "BetterAuthBannedUserError";
	}
}
