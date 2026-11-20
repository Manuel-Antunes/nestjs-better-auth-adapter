import type { BetterAuthBodyParserOptions } from "./body-parser-options.interface.ts";

// biome-ignore lint/suspicious/noExplicitAny: Better Auth's instance type depends on its options and plugins
export type Auth = any;

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
