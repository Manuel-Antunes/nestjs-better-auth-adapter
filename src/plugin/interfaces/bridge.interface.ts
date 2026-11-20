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
