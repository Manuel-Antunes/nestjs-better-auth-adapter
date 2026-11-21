import { type ExecutionContext, Inject } from "@nestjs/common";
import {
	AuthenticationProvider,
	type AuthenticationResult,
} from "@nestjs/authentication";
import { fromNodeHeaders } from "better-auth/node";
import { BetterAuthService } from "../better-auth.service.ts";
import { BetterAuthSessionError } from "../errors/better-auth-session.error.ts";
import { isCrossOriginWrite } from "../http/cross-origin.ts";
import { appendSetCookies } from "../http/set-cookie.ts";
import { cachedOriginCheck } from "../http/trusted-origins-cors.ts";
import type { BetterAuthRequest } from "../interfaces/better-auth-request.interface.ts";
import type {
	BetterAuthSession,
	BetterAuthUser,
} from "../interfaces/better-auth-session.interface.ts";
import { getAuthRequest, getResponseFromContext } from "../utils.ts";
import { assertNotBanned, checksBans } from "./banned-user.ts";
import { sessionAuthentication } from "./session-authentication.ts";

/**
 * Base class for Better Auth's session: the session cookie, and a Bearer
 * token too with the `bearer()` plugin, since `getSession()` reads both.
 * Extend it and register it, as Nest's `SessionCookieProvider`;
 * `BetterAuthService` is property-injected, so the subclass constructor
 * only lists its own dependencies:
 *
 * ```ts
 * @Injectable()
 * export class SessionAuth extends BetterAuthSessionProvider {
 *   constructor(registry: AuthenticationRegistry) {
 *     super();
 *     registry.registerProvider(this, { order: 0 });
 *   }
 * }
 * ```
 *
 * `@CurrentSession()` is Better Auth's session, additional fields and
 * plugin fields (`activeOrganizationId`…) included. The cookies
 * `getSession()` sets go out with the response, as on Better Auth's own
 * routes: the session's sliding expiry (`updateAge`), the cookie cache once
 * it lapsed, the cookies of an ended session cleared.
 *
 * As with `SessionCookieProvider`, the cookie on a cross-origin POST, PUT,
 * PATCH or DELETE, or on a cross-origin WebSocket handshake, counts as no
 * credentials, unless Better Auth trusts the origin (`trustedOrigins`).
 * Over WebSockets it reads socket.io's handshake, or the upgrade request
 * `WsAuthenticator` keeps on a `ws` client.
 *
 * It reads the request with {@link request} and sends the cookies with
 * {@link appendCookies}: override them for a transport of your own, as
 * `header()` on Nest's providers.
 *
 * A session satisfies `@Authenticate({ mfa: true })` once the `nestjs()`
 * plugin recorded a verified second factor on it (`mfaVerifiedAt`), never
 * because the user enrolled one: `twoFactor()` does not challenge magic
 * link, social or OAuth sign-ins.
 */
export abstract class BetterAuthSessionProvider extends AuthenticationProvider<
	BetterAuthUser,
	BetterAuthSession
> {
	@Inject(BetterAuthService) protected readonly betterAuth!: BetterAuthService;
	#checkBans?: boolean;
	#isTrustedOrigin?: Promise<(origin: string) => boolean>;

	async authenticate(
		context: ExecutionContext,
	): Promise<AuthenticationResult<BetterAuthUser, BetterAuthSession> | null> {
		const request = await this.request(context);
		if (!request) return null;
		const requestHeaders = fromNodeHeaders(request.headers);
		// The cookie on a write, or a WebSocket handshake, from an origin Better
		// Auth doesn't trust is ignored, as SessionCookieProvider does (CSRF,
		// cross-site WebSocket hijacking). A Bearer token still counts.
		if (
			requestHeaders.has("cookie") &&
			isCrossOriginWrite(request, await this.isTrustedOrigin())
		)
			requestHeaders.delete("cookie");
		const { headers, response: result } = await this.betterAuth.api.getSession({
			headers: requestHeaders,
			returnHeaders: true,
		});
		await this.appendCookies(context, headers?.getSetCookie?.() ?? []);
		// No credentials this provider understands: the guard tries the next one.
		if (!result) return null;

		const session = result.session as BetterAuthSession;
		const user = await this.validate(result.user as BetterAuthUser, session);
		if (!user) throw new BetterAuthSessionError();
		this.#checkBans ??= checksBans(this.betterAuth.instance);
		if (this.#checkBans) assertNotBanned(user);
		return sessionAuthentication(user, session);
	}

	/**
	 * The request behind a call: its headers, which `getSession()` reads
	 * (cookie, `Authorization`), and its method, which the cross-origin check
	 * reads. `undefined` when the transport has none: no credentials.
	 *
	 * By default the HTTP request (GraphQL's `context.req` included),
	 * socket.io's handshake or the upgrade request of a `ws` client, or the
	 * HTTP request an `@nestjs/mcp` or `@nestjs/ai` call arrived in. Override
	 * it for another transport.
	 */
	protected request(
		context: ExecutionContext,
	): BetterAuthRequest | undefined | Promise<BetterAuthRequest | undefined> {
		return getAuthRequest(context);
	}

	/**
	 * Sends the `Set-Cookie` headers `getSession()` answered with (the
	 * session's sliding expiry, the cookie cache, an ended session's cookies
	 * cleared). By default on the HTTP response (GraphQL's included); a
	 * transport without one, as WebSockets, drops them. Override it for
	 * another transport.
	 */
	protected async appendCookies(
		context: ExecutionContext,
		cookies: readonly string[],
	): Promise<void> {
		if (cookies.length > 0)
			appendSetCookies(
				(await getResponseFromContext(context)).response,
				cookies,
			);
	}

	/**
	 * The user a valid session signs in, or `null` to refuse it (a 401).
	 * Override it to add checks of your own; by default, the session's user.
	 * Users the `admin()` plugin banned are refused after it, whatever it
	 * returns.
	 */
	protected validate(
		user: BetterAuthUser,
		_session: BetterAuthSession,
	): BetterAuthUser | null | Promise<BetterAuthUser | null> {
		return user;
	}

	/** `WWW-Authenticate` challenge sent with a 401 when no provider found credentials. */
	challenge(): string {
		return "Cookie";
	}

	/** Better Auth's own origin check (`trustedOrigins`, wildcards included), remembered per origin. */
	private isTrustedOrigin(): Promise<(origin: string) => boolean> {
		this.#isTrustedOrigin ??= this.betterAuth.instance.$context.then(
			(ctx: { isTrustedOrigin(origin: string): boolean }) =>
				cachedOriginCheck((origin) => ctx.isTrustedOrigin(origin)),
		);
		return this.#isTrustedOrigin;
	}
}
