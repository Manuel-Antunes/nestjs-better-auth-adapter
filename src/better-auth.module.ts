import { Inject, Logger, Module } from "@nestjs/common";
import type {
	DynamicModule,
	MiddlewareConsumer,
	NestModule,
	OnModuleDestroy,
	OnModuleInit,
} from "@nestjs/common";
import { normalizePath } from "@nestjs/common/utils/shared.utils.js";
import {
	ApplicationConfig,
	DiscoveryModule,
	HttpAdapterHost,
} from "@nestjs/core";
import { mapToExcludeRoute } from "@nestjs/core/middleware/utils.js";
import { toNodeHandler } from "better-auth/node";
import { BetterAuthAccessControl } from "./access-control.ts";
import {
	type BetterAuthModuleAsyncOptions,
	BETTER_AUTH_MODULE_OPTIONS,
	type BetterAuthModuleOptions,
	ConfigurableModuleClass,
	type BetterAuthModuleForRootOptions,
} from "./better-auth.module-definition.ts";
import { BetterAuthService } from "./better-auth.service.ts";
import { BetterAuthHandlersWiring } from "./handlers.wiring.ts";
import { BetterAuthHooksExplorer } from "./hooks/hooks.explorer.ts";
import { configureFastifyBodyParser } from "./http/fastify-body-parser.ts";
import { handleFastifyTrustedOriginsCors } from "./http/fastify-trusted-origins-cors.ts";
import {
	SkipBodyParsingMiddleware,
	getNodeRequest,
	getNodeResponse,
	matchesBasePath,
	resolveBodyParserOptions,
} from "./http/middlewares.ts";
import { resetBridge } from "./plugin/bridge.ts";
import { bridgeOf } from "./plugins.ts";
import { BetterAuthApiKeyProvider } from "./providers/better-auth-api-key.provider.ts";
import { BetterAuthJwtProvider } from "./providers/better-auth-jwt.provider.ts";
import { BetterAuthSessionProvider } from "./providers/better-auth-session.provider.ts";

/**
 * Better Auth for Nest, through `@nestjs/authentication`:
 *
 * - serves Better Auth's routes under its `basePath`, and re-adds body
 *   parsing for every other route;
 * - registers Better Auth's credential providers in `AuthenticationRegistry`,
 *   so `AuthenticationGuard`, `@CurrentUser()`, `@CurrentSession()`,
 *   `@Authenticate()` and `AuthenticationContext` work as the Nest docs
 *   describe;
 * - plugs the Nest handlers, `OidcAccountResolver` and `PasswordHasher` it
 *   finds into Better Auth, and runs `@Hook()` / `@DatabaseHook()` providers
 *   inside it, through the `nestjs()` plugin.
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
		BetterAuthSessionProvider,
		BetterAuthJwtProvider,
		BetterAuthApiKeyProvider,
		BetterAuthHooksExplorer,
		BetterAuthHandlersWiring,
	],
	exports: [
		BETTER_AUTH_MODULE_OPTIONS,
		BetterAuthService,
		BetterAuthAccessControl,
		BetterAuthSessionProvider,
		BetterAuthJwtProvider,
		BetterAuthApiKeyProvider,
	],
})
export class BetterAuthModule
	extends ConfigurableModuleClass
	implements NestModule, OnModuleInit, OnModuleDestroy
{
	private readonly logger = new Logger(BetterAuthModule.name);
	private readonly basePath: string;

	constructor(
		@Inject(ApplicationConfig) applicationConfig: ApplicationConfig,
		@Inject(HttpAdapterHost) private readonly adapterHost: HttpAdapterHost,
		@Inject(BETTER_AUTH_MODULE_OPTIONS)
		private readonly options: BetterAuthModuleOptions,
	) {
		super();
		this.basePath = normalizePath(
			this.options.auth.options.basePath ?? "/api/auth",
		);

		// Better Auth's routes stay where Better Auth says they are, whatever
		// the global prefix.
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

	/** Fails at startup without the `nestjs()` plugin, rather than at the first hook. */
	onModuleInit(): void {
		bridgeOf(this.options.auth);
	}

	/** Takes this app's hooks out of the `auth` instance, which may outlive it. */
	onModuleDestroy(): void {
		resetBridge(bridgeOf(this.options.auth));
	}

	/** Mounts Better Auth's handler, its CORS and the body parsers on the HTTP adapter. */
	configure(consumer: MiddlewareConsumer): void {
		if (this.options.routes === false) return;

		const httpAdapter = this.adapterHost.httpAdapter;
		const isFastify = httpAdapter.getType() === "fastify";
		const bodyParser = resolveBodyParserOptions(this.options);
		const trustedOrigins = this.options.auth.options.trustedOrigins;
		const cors = this.options.trustedOriginsCors !== false && !!trustedOrigins;

		// A function needs a Fetch `Request` to evaluate, which Nest's
		// adapters don't provide.
		if (cors && !Array.isArray(trustedOrigins))
			throw new Error(
				"Better Auth's trustedOrigins must be a string array for BetterAuthModule's CORS. Use an array, or set trustedOriginsCors: false and configure CORS yourself.",
			);

		if (cors && !isFastify) {
			httpAdapter.enableCors({
				origin: trustedOrigins,
				methods: ["GET", "POST", "PUT", "DELETE"],
				credentials: true,
			});
		}

		if (isFastify) {
			configureFastifyBodyParser(httpAdapter, bodyParser);
		} else {
			consumer
				.apply(
					SkipBodyParsingMiddleware({ basePath: this.basePath, bodyParser }),
				)
				.forRoutes("*path");
		}

		const handler = toNodeHandler(this.options.auth);
		httpAdapter.use(
			(
				// biome-ignore lint/suspicious/noExplicitAny: the request type depends on the HTTP adapter
				req: any,
				// biome-ignore lint/suspicious/noExplicitAny: the response type depends on the HTTP adapter
				res: any,
				next: () => void,
			) => {
				if (!matchesBasePath(req, this.basePath)) return next();
				if (
					isFastify &&
					cors &&
					handleFastifyTrustedOriginsCors(req, res, { trustedOrigins })
				)
					return;

				const nodeReq = getNodeRequest(req);
				const nodeRes = getNodeResponse(res);
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
