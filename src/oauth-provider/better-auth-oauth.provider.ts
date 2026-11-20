import {
	type ExecutionContext,
	Inject,
	type OnModuleInit,
	Optional,
} from "@nestjs/common";
import { HttpAdapterHost, Reflector } from "@nestjs/core";
import {
	AuthenticationProvider,
	JwtClaims,
	type AuthenticationResult,
} from "@nestjs/authentication";
import { isAPIError } from "better-auth/api";
import {
	createDpopReplayStore,
	type DpopReplayStore,
} from "better-auth/oauth2";
import { BetterAuthService } from "../better-auth.service.ts";
import { BetterAuthConfigurationError } from "../errors/better-auth-configuration.error.ts";
import type { BetterAuthUser } from "../interfaces/better-auth-session.interface.ts";
import { isOAuthAccessToken } from "../oauth/access-token.ts";
import { assertNotBanned, checksBans } from "../providers/banned-user.ts";
import { getRequestFromContext } from "../utils.ts";
import { OAuthAccessTokenError } from "./errors/oauth-access-token.error.ts";
import { OAuthAccessTokenNotAcceptedError } from "./errors/oauth-access-token-not-accepted.error.ts";
import { OAuthInsufficientScopeError } from "./errors/oauth-insufficient-scope.error.ts";
import { OAuthUserRequiredError } from "./errors/oauth-user-required.error.ts";
import type { BetterAuthOAuthProviderOptions } from "./interfaces/better-auth-oauth-provider-options.interface.ts";
import type { BetterAuthOAuthAccessToken } from "./interfaces/oauth-access-token.interface.ts";
import type { OAuthResourceSettings } from "./interfaces/oauth-resource.interface.ts";
import { OAUTH_SCOPES } from "./oauth-scopes.decorator.ts";
import { OAuthResourceDocuments } from "./oauth-resource-documents.ts";
import {
	assertOAuthResourceServer,
	resolveOAuthResource,
	resourceClientOf,
} from "./resource-server.ts";

/**
 * Base class for the access tokens of Better Auth's `oauthProvider()`
 * plugin (`@better-auth/oauth-provider`): this API as an OAuth 2.1 resource
 * server for the apps users grant access to. Extend it and register it with
 * this API's resource identifier; `BetterAuthService` is property-injected:
 *
 * ```ts
 * @Injectable()
 * export class OAuthAuth extends BetterAuthOAuthProvider {
 *   constructor(registry: AuthenticationRegistry) {
 *     super({ audience: 'https://api.example.com' });
 *     registry.registerProvider(this, { order: 3 });
 *   }
 * }
 * ```
 *
 * - Verifies JWT access tokens (`typ: at+jwt`, RFC 9068) with the plugin's
 *   own resource client: signature against the `jwt()` keys, read
 *   in-process, issuer, audience, expiry, and DPoP proofs when the token is
 *   sender-constrained (`Authorization: DPoP`). Clients get these by
 *   requesting the `resource`; the plugin issues opaque tokens without one,
 *   which are meant for its `userinfo` endpoint only.
 * - Routes accept them only with `@OAuthScopes()`, and only when they carry
 *   its scopes: a 403 with RFC 6750's `insufficient_scope` challenge
 *   otherwise. A user's token never stands for their whole session.
 * - `@CurrentUser()` is the user who granted the token, and
 *   `@CurrentSession()` its claims ({@link BetterAuthOAuthAccessToken}).
 *   Tokens of the `client_credentials` grant have no user, and are refused
 *   with a 403 `user_required`, unless `validate()` returns a principal for
 *   the client: `TPrincipal` types it, and the user is then
 *   `BetterAuthUser | TPrincipal`.
 * - 401s carry RFC 9728's `resource_metadata`, which points clients (MCP
 *   clients among them) to the authorization server.
 *   `BetterAuthOAuthProviderModule`, which the app imports, serves it.
 *
 * Never counts as a second factor.
 */
export abstract class BetterAuthOAuthProvider<
		TPrincipal extends object = BetterAuthUser,
	>
	extends AuthenticationProvider<
		BetterAuthUser | TPrincipal,
		BetterAuthOAuthAccessToken
	>
	implements OnModuleInit
{
	@Inject(BetterAuthService) protected readonly betterAuth!: BetterAuthService;
	@Inject(Reflector) private readonly reflector!: Reflector;
	@Inject(HttpAdapterHost) private readonly adapterHost!: HttpAdapterHost;
	// Optional, so a missing BetterAuthOAuthProviderModule gets a clear error.
	@Optional()
	@Inject(OAuthResourceDocuments)
	private readonly documents?: OAuthResourceDocuments;
	readonly #settings: OAuthResourceSettings;
	#checkBans?: boolean;
	#replayStore?: Promise<DpopReplayStore>;

	constructor(options: BetterAuthOAuthProviderOptions) {
		super();
		this.#settings = resolveOAuthResource(new.target.name, options);
	}

	/**
	 * Fails at startup without `BetterAuthOAuthProviderModule` or
	 * `oauthProvider()`, or on resource metadata the plugin refuses (an
	 * unknown scope), then hands the metadata to the module. A subclass's own
	 * `onModuleInit()` calls `super.onModuleInit()`.
	 */
	async onModuleInit(): Promise<void> {
		const name = this.constructor.name;
		if (!this.documents)
			throw new BetterAuthConfigurationError(
				`${name} needs BetterAuthOAuthProviderModule: import it, from 'nestjs-better-auth-adapter/oauth-provider', next to BetterAuthModule.`,
			);
		const auth = this.betterAuth.instance;
		assertOAuthResourceServer(auth, name);
		const settings = this.#settings;
		if (!settings.metadataPath) return;
		const client = await resourceClientOf(auth);
		this.documents.add(
			settings.metadataPath,
			name,
			JSON.stringify(
				await client.getProtectedResourceMetadata({
					resource: settings.audience,
					bearer_methods_supported: ["header"],
					...settings.metadata,
				}),
			),
		);
	}

	async authenticate(
		context: ExecutionContext,
	): Promise<AuthenticationResult<
		BetterAuthUser | TPrincipal,
		BetterAuthOAuthAccessToken
	> | null> {
		const settings = this.#settings;
		const authorization = this.header(context, "authorization");
		const presented = authorization && /^(\S+)\s+(\S+)$/.exec(authorization);
		if (!presented) return null;
		const [, scheme = "", token = ""] = presented;
		// Other Bearer tokens (sessions, jwt() JWTs, API keys) are left to their
		// providers; a DPoP token is only ever an access token.
		const dpop = /^dpop$/i.test(scheme);
		if (!dpop && !(/^bearer$/i.test(scheme) && isOAuthAccessToken(token)))
			return null;

		const scopes = this.reflector.getAllAndOverride<string[] | undefined>(
			OAUTH_SCOPES,
			[context.getHandler(), context.getClass()],
		);

		let claims: Record<string, unknown>;
		try {
			const client = await resourceClientOf(this.betterAuth.instance);
			claims = await client.verifyAccessTokenRequest(
				{
					authorizationHeader: authorization,
					dpopProofJwt: this.header(context, "dpop"),
					...(await this.target(context)),
				},
				{
					verifyOptions: {
						audience: settings.audience,
						// Session JWTs of jwt() share the keys, issuer and maybe the
						// audience: only these tell an access token apart.
						typ: "at+jwt",
						requiredClaims: ["azp"],
					},
					requiredScopes: scopes?.length ? scopes : undefined,
					dpop: { replayStore: await this.replayStore() },
				},
			);
		} catch (error) {
			throw this.refusal(context, error);
		}

		if (!scopes) throw new OAuthAccessTokenNotAcceptedError();

		const client = this.isClientCredentials(claims);
		// Two lookups by primary key, at once.
		const [user, sessionAlive] = await Promise.all([
			this.validate(claims),
			settings.checkSession && typeof claims.sid === "string"
				? this.sessionAlive(claims.sid)
				: true,
		]);
		if (!user) {
			if (client) throw new OAuthUserRequiredError();
			throw this.invalid(settings, "unknown user");
		}
		if (!sessionAlive) throw this.invalid(settings, "session ended");
		// A client's token has no user to ban. A user's always has one: their
		// ban applies whatever principal validate() built for them.
		this.#checkBans ??= checksBans(this.betterAuth.instance);
		if (this.#checkBans && !client) {
			const granter =
				"banned" in user
					? (user as BetterAuthUser)
					: await this.findUser(this.getSubject(claims));
			if (!granter) throw this.invalid(settings, "unknown user");
			assertNotBanned(granter);
		}

		const scope = typeof claims.scope === "string" ? claims.scope : undefined;
		return {
			user,
			session: {
				...claims,
				scopes: scope ? scope.split(" ") : [],
			} as BetterAuthOAuthAccessToken,
		};
	}

	/**
	 * Who a verified access token stands for: by default the user who
	 * granted it, its `sub` looked up, or `null` to refuse it (a 401; a 403
	 * `user_required` for a `client_credentials` token, which has no user).
	 * Override it to add checks, and call `super.validate()` to keep the
	 * lookup; or to admit `client_credentials` tokens, return a
	 * `TPrincipal` for the client when `isClientCredentials(claims)`.
	 *
	 * For a user's token, users the `admin()` plugin banned are refused
	 * after it, whatever it returns: a principal without the user's
	 * `banned` field costs a second lookup, which keeping `super.validate()`'s
	 * fields (`{ ...user, ... }`) avoids.
	 */
	protected async validate(
		claims: JwtClaims,
	): Promise<BetterAuthUser | TPrincipal | null> {
		return this.findUser(this.getSubject(claims));
	}

	/**
	 * Whether a verified access token is a `client_credentials` one: issued
	 * to a client for itself (`sub` is its `azp`), with no user.
	 */
	protected isClientCredentials(claims: JwtClaims): boolean {
		const subject = this.getSubject(claims);
		return !!subject && subject === claims.azp;
	}

	private async findUser(subject: string): Promise<BetterAuthUser | null> {
		if (!subject) return null;
		const ctx = await this.betterAuth.instance.$context;
		return (await ctx.internalAdapter.findUserById(
			subject,
		)) as BetterAuthUser | null;
	}

	/** Whether the session the token was issued from (`sid`) is still on, as introspection checks it. */
	private async sessionAlive(sid: string): Promise<boolean> {
		const ctx = await this.betterAuth.instance.$context;
		const session = await ctx.adapter.findOne<{ expiresAt: Date }>({
			model: "session",
			where: [{ field: "id", value: sid }],
			select: ["expiresAt"],
		});
		return !!session && new Date(session.expiresAt) >= new Date();
	}

	private getSubject(claims: Record<string, unknown>) {
		return String(claims.sub ?? "");
	}

	/** `WWW-Authenticate` challenge sent with a 401 when no provider found credentials. */
	challenge(): string {
		return `Bearer resource_metadata="${this.#settings.metadataUrl}"`;
	}

	/** The method and absolute URL a DPoP proof signs (`htm`, `htu`). */
	private async target(context: ExecutionContext) {
		const request = await getRequestFromContext(context);
		// A WebSocket's handshake (socket.io's, or the upgrade request
		// WsAuthenticator keeps on a `ws` client), else the HTTP request
		// (GraphQL's included).
		const handshake =
			context.getType() === "ws"
				? (request?.handshake ??
					(request?.request && {
						headers: request.request.headers,
						url: request.request.url,
						secure: !!request.request.socket?.encrypted,
					}))
				: undefined;
		const headers = handshake?.headers ?? request?.headers ?? {};
		const path = handshake?.url ?? request?.originalUrl ?? request?.url ?? "/";
		// Express and Fastify honor their `trust proxy` settings here.
		const protocol =
			request?.protocol ?? (handshake?.secure ? "https" : "http");
		const host =
			(!handshake && typeof request?.host === "string" && request.host) ||
			headers.host;
		return {
			method: handshake ? "GET" : (request?.method ?? "GET"),
			url: `${protocol}://${host ?? "localhost"}${path}`,
		};
	}

	private replayStore(): Promise<DpopReplayStore> {
		this.#replayStore ??= this.#settings.dpopReplayStore
			? Promise.resolve(this.#settings.dpopReplayStore)
			: this.betterAuth.instance.$context.then(createDpopReplayStore);
		return this.#replayStore;
	}

	/**
	 * The resource client's refusals, with their challenges: a 401 for a bad
	 * token, a 403 `insufficient_scope` naming the missing scopes.
	 */
	private refusal(context: ExecutionContext, error: unknown): unknown {
		if (!isAPIError(error)) return error;
		const status = error.statusCode;
		if (status !== 401 && status !== 403) return error;

		const body = (error.body ?? {}) as Record<string, unknown>;
		const challenge = challengeOf(error);
		const message =
			typeof body.error_description === "string"
				? body.error_description
				: error.message || "invalid access token";
		if (status === 401)
			return new OAuthAccessTokenError(message, {
				code: typeof body.error === "string" ? body.error : undefined,
				challenge,
				cause: error,
			});

		// The guard sends a challenge with 401s only.
		if (challenge && context.getType() === "http") {
			this.adapterHost.httpAdapter?.setHeader(
				context.switchToHttp().getResponse(),
				"WWW-Authenticate",
				challenge,
			);
		}
		const scope = challenge && /[\s,]scope="([^"]*)"/.exec(challenge)?.[1];
		return new OAuthInsufficientScopeError(
			message,
			scope ? scope.split(" ") : [],
			challenge,
		);
	}

	private invalid(settings: OAuthResourceSettings, description: string) {
		return new OAuthAccessTokenError(description, {
			challenge: `Bearer error="invalid_token", error_description="${description}", resource_metadata="${settings.metadataUrl}"`,
		});
	}
}

function challengeOf(error: { headers?: unknown }): string | undefined {
	const headers = error.headers;
	if (headers instanceof Headers)
		return headers.get("www-authenticate") ?? undefined;
	if (headers && typeof headers === "object") {
		const entry = Object.entries(headers).find(
			([name]) => name.toLowerCase() === "www-authenticate",
		);
		return typeof entry?.[1] === "string" ? entry[1] : undefined;
	}
	return undefined;
}
