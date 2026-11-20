import { Injectable, Logger } from "@nestjs/common";
import {
	AuthenticationRegistry,
	type OidcProfile,
} from "@nestjs/authentication";
import {
	BetterAuthOidcAccountResolver,
	BetterAuthService,
	type BetterAuthUser,
} from "nestjs-better-auth-adapter";
import { PlatformRole } from "../../authorization/enums/platform-role.enum.ts";
import type { Auth } from "../create-auth.ts";

/**
 * Which user a GitHub or Google identity belongs to. Registered as the
 * `oidc` handler of AuthenticationRegistry (with the `oidc` option in the
 * AuthenticationModule options), it plugs itself into Better Auth's own
 * gate, `user.validateUserInfo`, and is asked before Better Auth attaches an
 * identity to an existing user: a sign-in with a linked provider, a link by
 * email, or a signed-in user connecting one (`linkTo`). Returning that user
 * confirms; `null` refuses, and Better Auth stores nothing.
 *
 * The base class finds the user as Better Auth does, and Better Auth guards
 * against account pre-hijacking itself (`account.accountLinking` in
 * createAuth). This adds the app's own rule: platform admins sign in with
 * their password and a second factor, never through a provider.
 */
@Injectable()
export class AccountLinkingResolver extends BetterAuthOidcAccountResolver {
	private readonly logger = new Logger(AccountLinkingResolver.name);

	constructor(
		registry: AuthenticationRegistry,
		betterAuth: BetterAuthService<Auth>,
	) {
		// The base class plugs the registered resolver into Better Auth's
		// user.validateUserInfo gate at startup.
		super(registry, betterAuth);
		// From the constructor: the registry locks once the app has initialized.
		registry.registerHandler("oidc", this);
	}

	protected override validate(user: BetterAuthUser, profile: OidcProfile) {
		if (user.role === PlatformRole.Admin) {
			this.logger.warn(
				`Refused a ${profile.provider} identity for an admin account: admins sign in with a password and a second factor.`,
			);
			return null;
		}
		return user;
	}
}
