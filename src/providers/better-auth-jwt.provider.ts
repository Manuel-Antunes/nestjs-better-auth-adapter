import {
	type ExecutionContext,
	Inject,
	type OnModuleInit,
} from "@nestjs/common";
import {
	AuthenticationProvider,
	type AuthenticationResult,
} from "@nestjs/authentication";
import { BetterAuthService } from "../better-auth.service.ts";
import { BetterAuthConfigurationError } from "../errors/better-auth-configuration.error.ts";
import { BetterAuthJwtError } from "../errors/better-auth-jwt.error.ts";
import type { BetterAuthJwtProviderOptions } from "../interfaces/better-auth-providers.interface.ts";
import type { AnyBetterAuthService } from "../interfaces/better-auth-service.interface.ts";
import type { BetterAuthUser } from "../interfaces/better-auth-session.interface.ts";
import type { BetterAuthJwtClaims } from "../interfaces/jwt-claims.interface.ts";
import { findPlugin } from "../plugins.ts";
import { isOAuthAccessToken } from "../oauth/access-token.ts";
import { assertNotBanned, checksBans } from "./banned-user.ts";
import type { Auth } from "better-auth";
import type { jwt } from "better-auth/plugins/jwt";

const JWT_PATTERN = /^[\w-]+\.[\w-]+\.[\w-]+$/;

/**
 * Base class for `Authorization: Bearer <jwt>` with the JWTs Better Auth's
 * `jwt()` plugin issues (`/token`, `set-auth-jwt`), verified with the
 * plugin's JWKS: signature, expiry, issuer and audience. Extend it and
 * register it, as Nest's `JwtBearerProvider`; `BetterAuthService` is
 * property-injected:
 *
 * ```ts
 * @Injectable()
 * export class JwtAuth extends BetterAuthJwtProvider {
 *   constructor(registry: AuthenticationRegistry) {
 *     super({ realm: 'api' });
 *     registry.registerProvider(this, { order: 1 });
 *   }
 * }
 * ```
 *
 * Over socket.io it also reads `handshake.auth.token`. Tokens that are not
 * shaped like a JWT (no two dots) are left to the other providers, the
 * convention Nest uses so that JWT and API key providers can coexist. OAuth
 * access tokens of the `oauthProvider()` plugin (`typ: at+jwt`) are left to
 * `BetterAuthOAuthProvider`, which holds them to their scopes.
 */
export abstract class BetterAuthJwtProvider
	extends AuthenticationProvider<BetterAuthUser, BetterAuthJwtClaims>
	implements OnModuleInit
{
	@Inject(BetterAuthService)
	protected readonly betterAuth!: BetterAuthService<
		Auth<{
			baseURL: string;
			plugins: [ReturnType<typeof jwt>];
		}>
	>;
	protected readonly realm: string;
	#checkBans?: boolean;

	constructor(options: BetterAuthJwtProviderOptions = {}) {
		super();
		this.realm = options.realm ?? "api";
	}

	/**
	 * Fails at startup without the `jwt()` plugin, and when `verifyJWT()`
	 * would check neither the issuer nor the audience (no `baseURL`): the
	 * `jwt()` keys also sign the ID tokens `oauthProvider()` issues to other
	 * apps, which this provider would otherwise take for sign-ins. A
	 * subclass's own `onModuleInit()` calls `super.onModuleInit()`.
	 */
	async onModuleInit(): Promise<void> {
		const name = this.constructor.name;
		const auth = this.betterAuth.instance;
		const plugin = findPlugin(auth, "jwt");
		if (!plugin)
			throw new BetterAuthConfigurationError(
				`${name} verifies the JWTs of Better Auth's jwt() plugin: add it to betterAuth({ plugins }).`,
			);
		const ctx = await auth.$context;
		const baseURL =
			typeof ctx.options.baseURL === "string" ? ctx.options.baseURL : "";
		const jwtOptions = plugin.options?.jwt;
		if (!(jwtOptions?.issuer ?? baseURL) || !(jwtOptions?.audience ?? baseURL))
			throw new BetterAuthConfigurationError(
				`${name} needs the JWT issuer and audience checked: set Better Auth's baseURL (or BETTER_AUTH_URL), or jwt({ jwt: { issuer, audience } }).`,
			);
	}

	async authenticate(
		context: ExecutionContext,
	): Promise<AuthenticationResult<BetterAuthUser, BetterAuthJwtClaims> | null> {
		const token = this.token(context);
		if (!token || !JWT_PATTERN.test(token)) return null;
		// OAuth access tokens are signed with the same keys, and may share the
		// issuer and audience: they carry what a user granted another app, not
		// their session, so BetterAuthOAuthProvider checks them.
		if (isOAuthAccessToken(token)) return null;

		const payload = await this.verify(this.betterAuth.api, token);
		if (!payload?.sub) throw this.invalid("invalid token");

		const user = await this.validate(payload);
		if (!user) throw this.invalid("invalid token");
		this.#checkBans ??= checksBans(this.betterAuth.instance);
		if (this.#checkBans) assertNotBanned(user);

		return { user, session: payload };
	}

	/**
	 * The user a verified JWT signs in, or `null` to refuse it (a 401).
	 * Override it to add checks of your own; by default, the user of `sub`,
	 * looked up (call `super.validate()` to keep it). Users the `admin()`
	 * plugin banned are refused after it, whatever it returns.
	 */
	protected async validate(
		payload: BetterAuthJwtClaims,
	): Promise<BetterAuthUser | null> {
		const ctx = await this.betterAuth.instance.$context;
		return (await ctx.internalAdapter.findUserById(
			payload.sub,
		)) as BetterAuthUser | null;
	}

	/** `WWW-Authenticate` challenge sent with a 401 when no provider found credentials. */
	challenge(): string {
		return `Bearer realm="${this.realm}"`;
	}

	/**
	 * The token a call presents, else `undefined` (no credentials): the
	 * `Authorization: Bearer` token, read with `header()`, else socket.io's
	 * `handshake.auth.token`. Override it to read tokens elsewhere, or
	 * override `header()` to keep reading `Authorization`.
	 */
	protected token(context: ExecutionContext): string | undefined {
		const authorization = this.header(context, "authorization");
		if (authorization)
			return /^Bearer\s+(\S+)$/i.exec(authorization.trim())?.[1];
		if (context.getType() !== "ws") return undefined;
		const token = context.switchToWs().getClient()?.handshake?.auth?.token;
		return typeof token === "string" ? token : undefined;
	}

	private async verify(
		api: AnyBetterAuthService["api"],
		token: string,
	): Promise<BetterAuthJwtClaims | null> {
		try {
			return (await api.verifyJWT({ body: { token } }))?.payload ?? null;
		} catch {
			return null;
		}
	}

	/** A 401 for a bearer token that looks like a JWT but did not verify, with the RFC 6750 challenge. */
	private invalid(description: string): BetterAuthJwtError {
		return new BetterAuthJwtError(description, this.realm);
	}
}
