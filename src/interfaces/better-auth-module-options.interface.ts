import type { Auth as BetterAuth, BetterAuthOptions } from "better-auth";
import type { BetterAuthBodyParserOptions } from "./body-parser-options.interface.ts";

/**
 * A `betterAuth({...})` instance: `Auth<typeof options>` for one built with
 * those options. `Auth` alone takes any instance: Better Auth's type is
 * invariant in its options (`$context.adapter` uses them both ways), so
 * `Auth<BetterAuthOptions>` would refuse every concrete one.
 */
// biome-ignore lint/suspicious/noExplicitAny: the options of whichever instance the app built
export type Auth<Options extends BetterAuthOptions = any> = BetterAuth<Options>;

export type BetterAuthMiddleware = (
	// biome-ignore lint/suspicious/noExplicitAny: the request type depends on the HTTP adapter
	req: any,
	// biome-ignore lint/suspicious/noExplicitAny: the response type depends on the HTTP adapter
	res: any,
	next: (error?: unknown) => void,
) => void | Promise<void>;

export interface BetterAuthModuleOptions<A = Auth> {
	/** The `betterAuth({...})` instance. */
	auth: A;
	/**
	 * Serve Better Auth's routes (sign-up, sign-in, `/oauth2/*`...) and
	 * `oauthProvider()`'s discovery documents from this app. `false` for an
	 * app that holds the instance only to authenticate its callers, when
	 * another service serves them: nothing is mounted, Nest's own body parser
	 * stays in charge (leave it on), and `trustedOriginsCors`, `bodyParser`
	 * and `middleware` don't apply. Providers, hooks, handlers and
	 * `BetterAuthService` work the same.
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
	/** @deprecated `@thallesp/nestjs-better-auth`'s option, refused at startup: use `routes: false`. */
	disableControllers?: never;
	/** @deprecated `@thallesp/nestjs-better-auth`'s option, refused at startup: the guard is `@nestjs/authentication`'s, `AuthenticationModule.forRoot({ globalGuard: false })`. */
	disableGlobalAuthGuard?: never;
	/** @deprecated `@thallesp/nestjs-better-auth`'s option, refused at startup: use `trustedOriginsCors: false`. */
	disableTrustedOriginsCors?: never;
	/** @deprecated `@thallesp/nestjs-better-auth`'s option, refused at startup: use `bodyParser.json.enabled` and `bodyParser.urlencoded.enabled`. */
	disableBodyParser?: never;
	/** @deprecated `@thallesp/nestjs-better-auth`'s option, refused at startup: use `bodyParser.rawBody`. */
	enableRawBodyParser?: never;
}

/** What a `forRootAsync({ useClass })` or `useExisting` class implements. */
export interface BetterAuthOptionsFactory {
	createBetterAuthOptions():
		| BetterAuthModuleOptions
		| Promise<BetterAuthModuleOptions>;
}
