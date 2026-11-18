export * from "./access-control.ts";
export * from "./better-auth.module.ts";
export {
	type Auth,
	type BetterAuthBodyParserOptions,
	type BetterAuthJsonBodyParserOptions,
	type BetterAuthMiddleware,
	type BetterAuthModuleAsyncOptions,
	type BetterAuthModuleForRootOptions,
	/** @internal The base class of `BetterAuthModule`, exported for its declaration. */
	ConfigurableModuleClass as BetterAuthConfigurableModuleClass,
	type BetterAuthModuleOptions,
	type BetterAuthOptionsFactory,
	type BetterAuthProviderOptions,
	type BetterAuthUrlencodedBodyParserOptions,
	BETTER_AUTH_MODULE_OPTIONS,
} from "./better-auth.module-definition.ts";
export * from "./better-auth.service.ts";
export * from "./hooks/hook.decorators.ts";
export * from "./providers/better-auth-api-key.provider.ts";
export * from "./providers/better-auth-jwt.provider.ts";
export * from "./providers/better-auth-session.provider.ts";
export { findPlugin, hasPlugin } from "./plugins.ts";
export * from "./types.ts";
