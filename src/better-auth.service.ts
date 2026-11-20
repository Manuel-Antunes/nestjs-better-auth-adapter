import { Inject, Injectable, Optional } from "@nestjs/common";
import {
	AUTHENTICATION_MODULE_OPTIONS,
	type AuthenticationModuleOptions,
	type AuthenticationResult,
} from "@nestjs/authentication";
import type { Auth, BetterAuthOptions } from "better-auth";
import { BETTER_AUTH_MODULE_OPTIONS } from "./better-auth.module-definition.ts";
import { resolveBasePath } from "./http/base-path.ts";
import type { BetterAuthModuleOptions } from "./interfaces/better-auth-module-options.interface.ts";
import type { AnyBetterAuthService } from "./interfaces/better-auth-service.interface.ts";
import type {
	BetterAuthSession,
	BetterAuthUser,
} from "./interfaces/better-auth-session.interface.ts";
import type { AuthHookContext } from "./plugin/interfaces/bridge.interface.ts";
import { sessionAuthentication } from "./providers/session-authentication.ts";

/** What `getSession()` resolves: the session and its user. */
interface FoundSession {
	session: BetterAuthSession;
	user: BetterAuthUser;
}

/** `AuthenticationModule`'s options, kept for the Better Auth handlers. */
const authenticationOptions = new WeakMap<
	object,
	AuthenticationModuleOptions | undefined
>();

/**
 * @internal The `AuthenticationModule` options next to this Better Auth
 * instance: the pages of the links the handlers send, the `oidc` option.
 */
export function authenticationOptionsOf(
	service: AnyBetterAuthService,
): AuthenticationModuleOptions | undefined {
	return authenticationOptions.get(service);
}

/**
 * The Better Auth instance, injectable. Pass your instance's type to get the
 * plugin endpoints typed:
 *
 * @example
 * ```ts
 * constructor(private readonly betterAuth: BetterAuthService<typeof auth>) {}
 * ```
 */
@Injectable()
export class BetterAuthService<T extends { api: T["api"] } = Auth> {
	constructor(
		@Inject(BETTER_AUTH_MODULE_OPTIONS)
		private readonly options: BetterAuthModuleOptions<T>,
		@Optional()
		@Inject(AUTHENTICATION_MODULE_OPTIONS)
		authentication?: AuthenticationModuleOptions,
	) {
		authenticationOptions.set(this, authentication);
	}

	/** Better Auth's server-side API: `auth.api`. */
	get api(): T["api"] {
		return this.options.auth.api;
	}

	/**
	 * Where Better Auth's routes are served, like `/api/auth`: the path of its
	 * `baseURL`, else its `basePath`. Build links to its endpoints with it.
	 */
	get basePath(): string {
		// Every Better Auth instance has its options; T only types `api`.
		const auth = this.options.auth as unknown as { options: BetterAuthOptions };
		return resolveBasePath(auth.options);
	}

	/** The whole Better Auth instance. */
	get instance(): T {
		return this.options.auth;
	}

	/**
	 * The session a Better Auth hook's request carries (or `headers`), as
	 * `BetterAuthSessionProvider` reports it to Nest: `{ user, session }`,
	 * with `mfa: 'verified'` once it passed a second factor, or `null`. What
	 * `@Authenticate({ mfa: true })` checks on the app's routes, for checks
	 * of your own on Better Auth's:
	 *
	 * ```ts
	 * @BeforeHook('/admin/ban-user')
	 * async requireSecondFactor(ctx: AuthHookContext) {
	 *   const signedIn = await this.betterAuth.authenticate(ctx);
	 *   if (signedIn && signedIn.mfa !== 'verified') throw new APIError('UNAUTHORIZED', { code: 'MFA_REQUIRED' });
	 * }
	 * ```
	 *
	 * Given a hook's context, the session is resolved once per request:
	 * one Better Auth already resolved (an after hook, an earlier hook) is
	 * reused, and the one resolved here is left for the endpoint, which then
	 * doesn't read it again. It goes through `getSession()`, so a `bearer()`
	 * token counts, which `getSessionFromCtx(ctx)` in a before hook misses.
	 *
	 * Neither a subclass's `validate()` nor the provider's ban and
	 * cross-origin checks run: Better Auth's routes check their own callers.
	 */
	async authenticate(
		source: AuthHookContext | Headers,
	): Promise<AuthenticationResult<BetterAuthUser, BetterAuthSession> | null> {
		const api = this.options.auth.api as unknown as Auth["api"];
		if (source instanceof Headers) {
			const found = (await api.getSession({
				headers: source,
			})) as FoundSession | null;
			return found ? sessionAuthentication(found.user, found.session) : null;
		}

		const ctx = source;
		let found = ctx.context.session as FoundSession | null;
		if (!found) {
			const { headers, response } = await api.getSession({
				headers: ctx.headers ?? new Headers(),
				returnHeaders: true,
			});
			found = response as FoundSession | null;
			if (found) {
				// Better Auth's per-request session, which its endpoints read first.
				(ctx.context as { session: FoundSession | null }).session = found;
				// A refreshed session's cookies, which the endpoint won't set now.
				for (const cookie of headers?.getSetCookie?.() ?? [])
					ctx.responseHeaders?.append("set-cookie", cookie);
			}
		}
		return found ? sessionAuthentication(found.user, found.session) : null;
	}
}
