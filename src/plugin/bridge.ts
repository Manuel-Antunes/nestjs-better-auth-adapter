import type { NestBridge } from "./interfaces/bridge.interface.ts";

/** @internal Where the `nestjs()` plugin keeps its {@link NestBridge}. */
export const NEST_BRIDGE = Symbol.for("nestjs-better-auth-adapter:bridge");

/** @internal Marks the hooks `BetterAuthModule` adds, so it can take them out when the app closes. */
export const NEST_OWNED = Symbol.for("nestjs-better-auth-adapter:nest-owned");

/**
 * @internal Takes out what `BetterAuthModule` added, so an `auth` instance
 * reused by another app (tests that recreate it) doesn't run them twice.
 */
export function resetBridge(bridge: NestBridge): void {
	for (const hooks of [bridge.hooks.before, bridge.hooks.after]) {
		for (let i = hooks.length - 1; i >= 0; i--) {
			if ((hooks[i] as { [NEST_OWNED]?: true })[NEST_OWNED]) hooks.splice(i, 1);
		}
	}
	for (const model of Object.keys(bridge.databaseHooks)) {
		delete bridge.databaseHooks[model];
	}
	bridge.emit = undefined;
}
