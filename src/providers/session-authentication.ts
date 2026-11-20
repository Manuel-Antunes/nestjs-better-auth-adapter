import type { AuthenticationResult } from "@nestjs/authentication";
import type {
	BetterAuthSession,
	BetterAuthUser,
} from "../interfaces/better-auth-session.interface.ts";

/**
 * A Better Auth session as `@nestjs/authentication` sees it:
 * `mfa: 'verified'` once the `nestjs()` plugin recorded a verified second
 * factor on it (`mfaVerifiedAt`), never because the user enrolled one.
 * The one rule `BetterAuthSessionProvider` and
 * `BetterAuthService.authenticate()` share.
 */
export function sessionAuthentication(
	user: BetterAuthUser,
	session: BetterAuthSession,
): AuthenticationResult<BetterAuthUser, BetterAuthSession> {
	return {
		user,
		session,
		...(session.mfaVerifiedAt && { mfa: "verified" as const }),
	};
}
