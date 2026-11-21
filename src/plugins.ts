import { BetterAuthConfigurationError } from "./errors/better-auth-configuration.error.ts";
import type {
	BetterAuthPluginById,
	BetterAuthPluginHost,
	BetterAuthPluginId,
} from "./interfaces/better-auth-plugin.interface.ts";
import { NEST_BRIDGE } from "./plugin/bridge.ts";
import type { NestBridge } from "./plugin/interfaces/bridge.interface.ts";

/**
 * The configured Better Auth plugin with this `id`, if any, typed from
 * `auth`'s own type: `findPlugin(auth, "jwt")?.options` is the `jwt()`
 * options `auth` was built with, and an id its plugins don't list is a
 * type error. With an `Auth` that doesn't list them, any id, and Better
 * Auth's `BetterAuthPlugin`.
 */
export function findPlugin<
	A extends BetterAuthPluginHost,
	const Id extends BetterAuthPluginId<A>,
>(auth: A, id: Id): BetterAuthPluginById<A, Id> | undefined {
	return (auth?.options?.plugins ?? []).find((plugin) => plugin.id === id) as
		| BetterAuthPluginById<A, Id>
		| undefined;
}

/** Whether the Better Auth plugin with this `id` is configured, `id` typed as `findPlugin()`'s. */
export function hasPlugin<
	A extends BetterAuthPluginHost,
	const Id extends BetterAuthPluginId<A>,
>(auth: A, id: Id): boolean {
	return findPlugin(auth, id) !== undefined;
}

/**
 * The bridge of the `nestjs()` plugin, which `BetterAuthModule` needs to
 * run Nest providers inside Better Auth.
 */
export function bridgeOf(auth: BetterAuthPluginHost): NestBridge {
	const bridge = (
		findPlugin(auth, "nestjs") as { [NEST_BRIDGE]?: NestBridge } | undefined
	)?.[NEST_BRIDGE];
	if (!bridge)
		throw new BetterAuthConfigurationError(
			"BetterAuthModule needs Better Auth's nestjs() plugin: add it to betterAuth({ plugins: [nestjs()] }), imported from 'nestjs-better-auth-adapter/plugin'.",
		);
	return bridge;
}
