import type { BetterAuthPlugin } from "better-auth";
import type { createAuthMiddleware } from "better-auth/api";

/** The context Better Auth passes to a request hook handler. */
export type AuthHookContext = Parameters<
	Parameters<typeof createAuthMiddleware>[0]
>[0];

/** A request hook, as Better Auth plugins declare them. */
export type BridgeHook = NonNullable<
	NonNullable<BetterAuthPlugin["hooks"]>["after"]
>[number];

/**
 * What the `nestjs()` plugin shares with `BetterAuthModule`. Better Auth reads
 * a plugin's hooks on every request and keeps a reference to the database
 * hooks its `init()` returns, so the module can fill them once Nest has
 * created the providers that implement them.
 */
export interface NestBridge {
	hooks: { before: BridgeHook[]; after: BridgeHook[] };
	// biome-ignore lint/suspicious/noExplicitAny: shaped like Better Auth's `databaseHooks` option
	databaseHooks: Record<string, any>;
}

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
}
