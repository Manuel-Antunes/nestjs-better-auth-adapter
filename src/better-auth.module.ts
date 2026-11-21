import { Inject, Logger, Module } from "@nestjs/common";
import type {
	DynamicModule,
	MiddlewareConsumer,
	NestModule,
	OnModuleDestroy,
	OnModuleInit,
} from "@nestjs/common";
import {
	ApplicationConfig,
	DiscoveryModule,
	HttpAdapterHost,
} from "@nestjs/core";
import { mapToExcludeRoute } from "@nestjs/core/middleware/utils.js";
import { toNodeHandler } from "better-auth/node";
import { BetterAuthAccessControl } from "./access-control.ts";
import { BetterAuthEventsBinding } from "./authentication-events.binding.ts";
import {
	BETTER_AUTH_MODULE_OPTIONS,
	ConfigurableModuleClass,
} from "./better-auth.module-definition.ts";
import { BetterAuthConfigurationError } from "./errors/better-auth-configuration.error.ts";
import type { BetterAuthModuleOptions } from "./interfaces/better-auth-module-options.interface.ts";
import type {
	BetterAuthModuleAsyncOptions,
	BetterAuthModuleForRootOptions,
} from "./interfaces/better-auth-module-root-options.interface.ts";
import { BetterAuthService } from "./better-auth.service.ts";
import { BetterAuthOwnedStore } from "./storage/better-auth-owned.store.ts";
import { BetterAuthHandlersCheck } from "./handlers/handlers.check.ts";
import { BetterAuthHooksExplorer } from "./hooks/hooks.explorer.ts";
import { resolveBasePath } from "./http/base-path.ts";
import { configureFastifyBodyParser } from "./http/fastify-body-parser.ts";
import {
	fillCacheControl,
	resolveJwksCacheControl,
} from "./http/jwks-cache-control.ts";
import {
	cachedOriginCheck,
	handleTrustedOriginsCors,
} from "./http/trusted-origins-cors.ts";
import {
	SkipBodyParsingMiddleware,
	getNodeRequest,
	getNodeResponse,
	getRequestPath,
	matchesBasePath,
	resolveBodyParserOptions,
} from "./http/middlewares.ts";
import { oauthDiscoveryPaths } from "./oauth/discovery-paths.ts";
import { assertNoThallespOptions } from "./options/thallesp-options.ts";
import { BetterAuthPasswordHasherBinding } from "./password-hasher.binding.ts";
import { resetBridge } from "./plugin/bridge.ts";
import { bridgeOf } from "./plugins.ts";

/**
 * Better Auth for Nest, through `@nestjs/authentication`:
 *
 * - serves Better Auth's routes where Better Auth expects them (the path
 *   of its `baseURL`, else its `basePath`), and re-adds body parsing for
 *   every other route; `routes: false` serves none, for an app that only
 *   authenticates its callers;
 * - gives the credential providers the app extends (`BetterAuthSessionProvider`
 *   and the others) what they need, so `AuthenticationGuard`,
 *   `@CurrentUser()`, `@CurrentSession()`, `@Authenticate()` and
 *   `AuthenticationContext` work as the Nest docs describe;
 * - plugs the Nest handlers, `OidcAccountResolver` and `PasswordHasher` it
 *   finds into Better Auth, runs `@Hook()` / `@DatabaseHook()` providers
 *   inside it, and publishes its flows as `AuthenticationEvents`, through
 *   the `nestjs()` plugin;
 * - with `oauthProvider()`, serves its discovery documents outside the base
 *   path too, unless `routes: false`. Accepting its access tokens is
 *   `BetterAuthOAuthProviderModule`'s, from
 *   `nestjs-better-auth-adapter/oauth-provider`;
 * - with `jwt()`, sends its JWKS with a `Cache-Control`
 *   (`jwksCacheControl`), which Better Auth doesn't.
 *
 * It registers no credential provider: the app extends
 * `BetterAuthSessionProvider` and the others, and registers them in
 * `AuthenticationRegistry`, as with Nest's own providers.
 *
 * Import it after `AuthenticationModule.forRoot()`. Global by default.
 *
 * @example
 * ```ts
 * @Module({
 *   imports: [
 *     AuthenticationModule.forRoot(),
 *     BetterAuthModule.forRoot({ auth }),
 *   ],
 * })
 * export class AppModule {}
 * ```
 */
@Module({
	imports: [DiscoveryModule],
	providers: [
		BetterAuthService,
		BetterAuthAccessControl,
		BetterAuthHooksExplorer,
		BetterAuthHandlersCheck,
		BetterAuthPasswordHasherBinding,
		BetterAuthEventsBinding,
		BetterAuthOwnedStore,
	],
	exports: [
		BETTER_AUTH_MODULE_OPTIONS,
		BetterAuthService,
		BetterAuthAccessControl,
	],
})
export class BetterAuthModule
	extends ConfigurableModuleClass
	implements NestModule, OnModuleInit, OnModuleDestroy
{
	private readonly logger = new Logger(BetterAuthModule.name);
	private readonly basePath: string;
	/** Whether this app serves Better Auth's routes (`routes`). */
	private readonly servesRoutes: boolean;
	/** Paths outside `basePath` that Better Auth's handler answers. */
	private readonly discoveryPaths: Set<string>;
	/** The `jwt()` plugin's JWKS, and the `Cache-Control` it's sent with. */
	private readonly jwks?: { path: string; cacheControl: string };
	/** Better Auth's own origin check, once its context resolved. */
	private isTrustedOrigin?: (origin: string) => boolean;

	constructor(
		@Inject(ApplicationConfig) applicationConfig: ApplicationConfig,
		@Inject(HttpAdapterHost) private readonly adapterHost: HttpAdapterHost,
		@Inject(BETTER_AUTH_MODULE_OPTIONS)
		private readonly options: BetterAuthModuleOptions,
	) {
		super();
		assertNoThallespOptions(this.options);
		// Where Better Auth's router expects its routes: they are served there,
		// whatever the global prefix.
		this.basePath = resolveBasePath(this.options.auth.options);
		this.servesRoutes = this.options.routes !== false;
		if (!this.servesRoutes) {
			// Options of the handler and its parsers: silently ignoring them would
			// hide a misconfiguration (a webhook's `rawBody` that never comes).
			const ignored = (["bodyParser", "middleware"] as const).filter(
				(option) => this.options[option] !== undefined,
			);
			if (ignored.length)
				throw new BetterAuthConfigurationError(
					`BetterAuthModule's ${ignored.join(" and ")} only apply to Better Auth's routes, which routes: false doesn't serve: remove ${ignored.length > 1 ? "them" : "it"}, and configure Nest's own body parser.`,
				);
			if (typeof this.options.jwksCacheControl === "string")
				throw new BetterAuthConfigurationError(
					"BetterAuthModule's jwksCacheControl is for the JWKS Better Auth's routes serve, which routes: false doesn't: remove it, and send the header where the JWKS is served.",
				);
			this.discoveryPaths = new Set();
			return;
		}
		this.discoveryPaths = new Set(
			oauthDiscoveryPaths(this.options.auth, this.basePath),
		);
		this.jwks = resolveJwksCacheControl(
			this.options.auth,
			this.basePath,
			this.options.jwksCacheControl,
		);
		const prefixOptions = applicationConfig.getGlobalPrefixOptions();
		applicationConfig.setGlobalPrefixOptions({
			...prefixOptions,
			exclude: [
				...(prefixOptions.exclude ?? []),
				...mapToExcludeRoute([this.basePath, `${this.basePath}/*path`]),
			],
		});
	}

	static forRoot(options: BetterAuthModuleForRootOptions): DynamicModule {
		return super.forRoot(options);
	}

	static forRootAsync(options: BetterAuthModuleAsyncOptions): DynamicModule {
		return super.forRootAsync(options);
	}

	/**
	 * Fails at startup without the `nestjs()` plugin, rather than at the first
	 * hook.
	 */
	async onModuleInit(): Promise<void> {
		bridgeOf(this.options.auth);
		if (this.servesRoutes && this.options.trustedOriginsCors !== false) {
			const ctx = await this.options.auth.$context;
			this.isTrustedOrigin = cachedOriginCheck((origin) =>
				ctx.isTrustedOrigin(origin),
			);
		}
	}

	/** Takes this app's hooks out of the `auth` instance, which may outlive it. */
	onModuleDestroy(): void {
		resetBridge(bridgeOf(this.options.auth));
	}

	/** Mounts Better Auth's handler, its CORS and the body parsers on the HTTP adapter. */
	configure(_consumer: MiddlewareConsumer): void {
		if (!this.servesRoutes) {
			this.logger.log(
				"Better Auth's routes are not served by this app (routes: false)",
			);
			return;
		}
		const httpAdapter = this.adapterHost.httpAdapter;
		const isFastify = httpAdapter.getType() === "fastify";
		const bodyParser = resolveBodyParserOptions(this.options);
		const trustedOrigins = this.options.auth.options.trustedOrigins;
		const cors = this.options.trustedOriginsCors !== false;

		// A function needs a Fetch `Request` to evaluate, which Nest's
		// adapters don't provide.
		if (cors && trustedOrigins && !Array.isArray(trustedOrigins))
			throw new BetterAuthConfigurationError(
				"Better Auth's trustedOrigins must be a string array for BetterAuthModule's CORS. Use an array, or set trustedOriginsCors: false and configure CORS yourself.",
			);

		if (isFastify) {
			configureFastifyBodyParser(httpAdapter, bodyParser);
		} else {
			// On the adapter rather than through the MiddlewareConsumer, which
			// would apply the global prefix: routes outside it (GraphQL, the
			// prefix's `exclude`) need their bodies parsed too.
			httpAdapter.use(
				SkipBodyParsingMiddleware({ basePath: this.basePath, bodyParser }),
			);
		}

		const handler = toNodeHandler(this.options.auth);
		const jwks = this.jwks;
		httpAdapter.use(
			(
				// biome-ignore lint/suspicious/noExplicitAny: the request type depends on the HTTP adapter
				req: any,
				// biome-ignore lint/suspicious/noExplicitAny: the response type depends on the HTTP adapter
				res: any,
				next: () => void,
			) => {
				const path = getRequestPath(req).split("?", 1)[0] ?? "";
				if (
					!matchesBasePath(req, this.basePath) &&
					!this.discoveryPaths.has(path)
				)
					return next();
				// Only Better Auth's routes: CORS for the app's own is the app's
				// (`app.enableCors()`).
				const isTrustedOrigin = this.isTrustedOrigin;
				if (
					cors &&
					isTrustedOrigin &&
					handleTrustedOriginsCors(req, res, { isTrustedOrigin })
				)
					return;

				const nodeReq = getNodeRequest(req);
				const nodeRes = getNodeResponse(res);
				if (jwks && path.replace(/\/+$/, "") === jwks.path)
					fillCacheControl(nodeRes, jwks.cacheControl);
				if (this.options.middleware) {
					return this.options.middleware(req, res, () =>
						handler(nodeReq, nodeRes),
					);
				}
				return handler(nodeReq, nodeRes);
			},
		);
		this.logger.log(`Better Auth is served on '${this.basePath}'`);
	}
}
