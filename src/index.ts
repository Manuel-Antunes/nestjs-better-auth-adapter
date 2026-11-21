export * from "./access-control.ts";
export * from "./better-auth.module.ts";
export {
	/** @internal The base class of `BetterAuthModule`, exported for its declaration. */
	ConfigurableModuleClass as BetterAuthConfigurableModuleClass,
	BETTER_AUTH_MODULE_OPTIONS,
} from "./better-auth.module-definition.ts";
export * from "./better-auth.service.ts";
export * from "./errors/index.ts";
export * from "./handlers/index.ts";
export * from "./hooks/hook.decorators.ts";
export type {
	AccessControlScope,
	BetterAuthACPolicyMetadata,
	BetterAuthAccessControlOptions,
	BuildAccessControlOptions,
} from "./interfaces/access-control.interface.ts";
export type * from "./interfaces/better-auth-module-options.interface.ts";
export type * from "./interfaces/better-auth-module-root-options.interface.ts";
export type {
	BetterAuthPluginById,
	BetterAuthPluginHost,
	BetterAuthPluginId,
	BetterAuthPluginOf,
} from "./interfaces/better-auth-plugin.interface.ts";
export type * from "./interfaces/better-auth-api-key.interface.ts";
export type * from "./interfaces/better-auth-providers.interface.ts";
export type { BetterAuthRequest } from "./interfaces/better-auth-request.interface.ts";
export type * from "./interfaces/better-auth-service.interface.ts";
export type * from "./interfaces/better-auth-session.interface.ts";
export type * from "./interfaces/handler-links.interface.ts";
export type {
	BetterAuthBodyParserOptions,
	BetterAuthJsonBodyParserOptions,
	BetterAuthUrlencodedBodyParserOptions,
} from "./interfaces/body-parser-options.interface.ts";
export type {
	DatabaseHookModel,
	DatabaseHookOperation,
} from "./interfaces/hooks.interface.ts";
export type * from "./interfaces/jwt-claims.interface.ts";
export type { AuthHookContext } from "./plugin/interfaces/bridge.interface.ts";
export { findPlugin, hasPlugin } from "./plugins.ts";
export * from "./providers/better-auth-api-key.provider.ts";
export * from "./providers/better-auth-jwt.provider.ts";
export * from "./providers/better-auth-session.provider.ts";
export { BetterAuthConfigAugmenter } from "./config/better-auth-config-augmenter.ts";
export { BetterAuthPluginConfigAugmenter } from "./config/better-auth-plugin-config-augmenter.ts";
export type {
	BetterAuthAugmentOptions,
	BetterAuthCallback,
	BetterAuthCallbackAt,
	BetterAuthCallbackPath,
	BetterAuthConfigHost,
	BetterAuthPluginCallbackPath,
	BetterAuthPluginOptions,
} from "./interfaces/better-auth-config-augmenter.interface.ts";
