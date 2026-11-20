import { BetterAuthConfigurationError } from "./errors/better-auth-configuration.error.ts";
import type { Auth } from "./interfaces/better-auth-module-options.interface.ts";
import type { PluginLike } from "./interfaces/better-auth-plugin.interface.ts";
import { NEST_BRIDGE } from "./plugin/bridge.ts";
import type { NestBridge } from "./plugin/interfaces/bridge.interface.ts";

/** The configured Better Auth plugin with this `id`, if any. */
export const findPlugin = (auth: Auth, id: string): PluginLike | undefined =>
	((auth?.options?.plugins ?? []) as PluginLike[]).find(
		(plugin) => plugin.id === id,
	);

/** Whether the Better Auth plugin with this `id` is configured. */
export const hasPlugin = (auth: Auth, id: string): boolean =>
	findPlugin(auth, id) !== undefined;

/**
 * The bridge of the `nestjs()` plugin, which `BetterAuthModule` needs to
 * run Nest providers inside Better Auth.
 */
export function bridgeOf(auth: Auth): NestBridge {
	const bridge = (
		findPlugin(auth, "nestjs") as { [NEST_BRIDGE]?: NestBridge } | undefined
	)?.[NEST_BRIDGE];
	if (!bridge)
		throw new BetterAuthConfigurationError(
			"BetterAuthModule needs Better Auth's nestjs() plugin: add it to betterAuth({ plugins: [nestjs()] }), imported from 'nestjs-better-auth-adapter/plugin'.",
		);
	return bridge;
}
