import type { Auth } from "./better-auth.module-definition.ts";
import { NEST_BRIDGE, type NestBridge } from "./plugin/bridge.ts";

type PluginLike = { id: string; options?: Record<string, unknown> };

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
		throw new Error(
			"BetterAuthModule needs Better Auth's nestjs() plugin: add it to betterAuth({ plugins: [nestjs()] }), imported from 'nestjs-better-auth-adapter/plugin'.",
		);
	return bridge;
}
