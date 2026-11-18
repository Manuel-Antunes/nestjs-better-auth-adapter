import { ConfigurableModuleBuilder } from "@nestjs/common";
import type {
	JsonBodyParserOptions,
	UrlencodedBodyParserOptions,
} from "./http/body-parser-options.ts";

// biome-ignore lint/suspicious/noExplicitAny: Better Auth's instance type depends on its options and plugins
export type Auth = any;

export type BetterAuthJsonBodyParserOptions = JsonBodyParserOptions & {
	/** @default true */
	enabled?: boolean;
};

export type BetterAuthUrlencodedBodyParserOptions =
	UrlencodedBodyParserOptions & {
		/** @default true */
		enabled?: boolean;
	};

/**
 * Better Auth reads the raw request body of its own routes, so Nest's body
 * parser has to be turned off (`bodyParser: false` in `NestFactory.create()`).
 * These options configure the parsers this module adds back for every other
 * route.
 */
export type BetterAuthBodyParserOptions = {
	json?: BetterAuthJsonBodyParserOptions;
	urlencoded?: BetterAuthUrlencodedBodyParserOptions;
	/**
	 * Attach the raw request buffer to `req.rawBody`, for webhook signature
	 * checks. Nest's own `rawBody: true` has no effect once its body parser is
	 * off: use this instead.
	 * @default false
	 */
	rawBody?: boolean;
};

export type BetterAuthMiddleware = (
	// biome-ignore lint/suspicious/noExplicitAny: the request type depends on the HTTP adapter
	req: any,
	// biome-ignore lint/suspicious/noExplicitAny: the response type depends on the HTTP adapter
	res: any,
	next: (error?: unknown) => void,
) => void | Promise<void>;

/** A Better Auth credential provider: its place in `AuthenticationRegistry`'s chain, or `false` to leave it out. */
export type BetterAuthProviderOptions<T = object> =
	| (T & {
			/** Position in the chain; the first provider that returns a user wins. */
			order?: number;
	  })
	| false;

export interface BetterAuthModuleOptions<A = Auth> {
	/** The `betterAuth({...})` instance. */
	auth: A;
	/**
	 * The credential providers this module registers in `@nestjs/authentication`'s
	 * chain. The JWT and API key providers only register when their Better Auth
	 * plugin is configured.
	 */
	providers?: {
		/** Session cookie, and Bearer token with the `bearer()` plugin. @default { order: 0 } */
		session?: BetterAuthProviderOptions;
		/** JWTs from the `jwt()` plugin. @default { order: 1 } */
		jwt?: BetterAuthProviderOptions;
		/** Keys from the `apiKey()` plugin. @default { order: 2, realm: 'api' } */
		apiKey?: BetterAuthProviderOptions<{
			/** `realm` of the `WWW-Authenticate` challenge. */
			realm?: string;
			/**
			 * The headers keys are read from: set it to the `apiKey()` plugin's
			 * `apiKeyHeaders` when you changed those.
			 * @default 'x-api-key'
			 */
			headers?: string | string[];
		}>;
	};
	/**
	 * Serve Better Auth's routes under its `basePath`. Turn it off to mount
	 * the handler yourself.
	 * @default true
	 */
	routes?: boolean;
	/**
	 * Enable CORS for Better Auth's `trustedOrigins` (a string array). Turn it
	 * off to configure CORS yourself.
	 * @default true
	 */
	trustedOriginsCors?: boolean;
	bodyParser?: BetterAuthBodyParserOptions;
	/** Wraps Better Auth's handler, e.g. for request-scoped contexts like MikroORM's `RequestContext`. */
	middleware?: BetterAuthMiddleware;
}

/** What a `forRootAsync({ useClass })` or `useExisting` class implements. */
export interface BetterAuthOptionsFactory {
	createBetterAuthOptions():
		| BetterAuthModuleOptions
		| Promise<BetterAuthModuleOptions>;
}

export const BETTER_AUTH_MODULE_OPTIONS = Symbol.for(
	"nestjs-better-auth-adapter:module-options",
);

export const {
	ConfigurableModuleClass,
	OPTIONS_TYPE,
	ASYNC_OPTIONS_TYPE,
	MODULE_OPTIONS_TOKEN,
} = new ConfigurableModuleBuilder<BetterAuthModuleOptions>({
	optionsInjectionToken: BETTER_AUTH_MODULE_OPTIONS,
})
	.setClassMethodName("forRoot")
	.setFactoryMethodName("createBetterAuthOptions")
	.setExtras({ isGlobal: true }, (definition, extras) => ({
		...definition,
		global: extras.isGlobal,
	}))
	.build();

/** What `forRoot()` takes: the options, and `isGlobal` (default `true`). */
export type BetterAuthModuleForRootOptions = typeof OPTIONS_TYPE;

/** What `forRootAsync()` takes: `useFactory`, `useClass` or `useExisting`, with `imports` and `inject`. */
export type BetterAuthModuleAsyncOptions = typeof ASYNC_OPTIONS_TYPE;
