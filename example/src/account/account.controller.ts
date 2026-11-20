import { Controller, Get } from "@nestjs/common";
import {
	Authenticate,
	CurrentSession,
	CurrentUser,
} from "@nestjs/authentication";
import { Can } from "@nestjs/authorization";
import { BetterAuthSessionProvider } from "nestjs-better-auth-adapter";
import type { Session, User } from "../auth/auth.types.ts";

/**
 * The signed-in user, as the app sees them. Everything else about the
 * account (profile, sessions, API keys, two-factor) is Better Auth's own
 * routes under /api/auth, with their own checks: the app doesn't wrap them.
 *
 * `@Can.Anyone()`: any signed-in user. Only a session (cookie or bearer
 * token) reaches these routes, since `@CurrentSession()` is then Better
 * Auth's session; a JWT's would be its claims, an API key's the key.
 */
@Controller("me")
@Can.Anyone()
@Authenticate({ providers: [BetterAuthSessionProvider] })
export class AccountController {
	/** Better Auth's user and session, plugin and additional fields included. */
	@Get()
	me(@CurrentUser() user: User, @CurrentSession() session: Session) {
		return {
			user,
			session: {
				id: session.id,
				expiresAt: session.expiresAt,
				activeOrganizationId: session.activeOrganizationId,
				mfaVerified: !!session.mfaVerifiedAt,
			},
		};
	}

	/** One field of the user: `@CurrentUser('locale')` (an additional field). */
	@Get("locale")
	locale(@CurrentUser("locale") locale: string | null | undefined) {
		return { locale: locale ?? "en" };
	}
}
