import { type ExecutionContext, Inject, Injectable } from "@nestjs/common";
import {
	AuthenticationProvider,
	AuthenticationRegistry,
	type AuthenticationResult,
} from "@nestjs/authentication";
import { fromNodeHeaders } from "better-auth/node";
import {
	BETTER_AUTH_MODULE_OPTIONS,
	type BetterAuthModuleOptions,
} from "../better-auth.module-definition.ts";
import { BetterAuthService } from "../better-auth.service.ts";
import type { BetterAuthSession, BetterAuthUser } from "../types.ts";
import { getRequestFromContext } from "../utils.ts";

/**
 * Authenticates with Better Auth's session: the session cookie, and a Bearer
 * token too with the `bearer()` plugin, since `getSession()` reads both.
 * `@CurrentSession()` is Better Auth's session, additional fields and
 * plugin fields (`activeOrganizationId`…) included.
 *
 * A session satisfies `@Authenticate({ mfa: true })` once the `nestjs()`
 * plugin recorded a verified second factor on it (`mfaVerifiedAt`), never
 * because the user enrolled one: `twoFactor()` does not challenge magic
 * link, social or OAuth sign-ins.
 */
@Injectable()
export class BetterAuthSessionProvider extends AuthenticationProvider<
	BetterAuthUser,
	BetterAuthSession
> {
	constructor(
		@Inject(BetterAuthService) private readonly betterAuth: BetterAuthService,
		@Inject(BETTER_AUTH_MODULE_OPTIONS) options: BetterAuthModuleOptions,
		@Inject(AuthenticationRegistry) registry: AuthenticationRegistry,
	) {
		super();
		const settings = options.providers?.session;
		if (settings !== false) {
			registry.registerProvider(this, { order: settings?.order ?? 0 });
		}
	}

	async authenticate(
		context: ExecutionContext,
	): Promise<AuthenticationResult<BetterAuthUser, BetterAuthSession> | null> {
		const request = await getRequestFromContext(context);
		const result = await this.betterAuth.api.getSession({
			headers: fromNodeHeaders(
				request?.headers ?? request?.handshake?.headers ?? {},
			),
		});
		// No credentials this provider understands: the guard tries the next one.
		if (!result) return null;

		const session = result.session as BetterAuthSession;
		return {
			user: result.user as BetterAuthUser,
			session,
			...(session.mfaVerifiedAt && { mfa: "verified" as const }),
		};
	}

	/** `WWW-Authenticate` challenge sent with a 401 when no provider found credentials. */
	challenge(): string {
		return "Cookie";
	}
}
