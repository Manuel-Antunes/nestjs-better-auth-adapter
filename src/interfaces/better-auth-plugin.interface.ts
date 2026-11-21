import type { BetterAuthPlugin, IsAny } from "better-auth";

/**
 * What the plugin helpers (`findPlugin()`, `hasPlugin()`) read of a Better
 * Auth instance: its plugins. Any `betterAuth({...})` instance is one.
 */
export interface BetterAuthPluginHost {
	options: { plugins?: readonly BetterAuthPlugin[] | undefined };
}

/**
 * The plugins `A`'s type lists; Better Auth's `BetterAuthPlugin` when its
 * type doesn't tell (`Auth`, whose options are any instance's).
 */
export type BetterAuthPluginOf<A extends BetterAuthPluginHost> = IsAny<
	A["options"]["plugins"]
> extends true
	? BetterAuthPlugin
	: NonNullable<A["options"]["plugins"]>[number];

/**
 * The ids of the plugins `A`'s type lists (`"jwt" | "bearer"`…), each read
 * from its own plugin: any string when the type doesn't list them, as
 * `Auth`'s.
 */
export type BetterAuthPluginId<A extends BetterAuthPluginHost> =
	BetterAuthPluginOf<A> extends infer Plugin
		? Plugin extends { id: infer Id extends string }
			? Id
			: never
		: never;

/**
 * The plugin of `A` whose id is `Id`, with its own type (its `options`…)
 * when `A`'s type lists it; else Better Auth's `BetterAuthPlugin`.
 */
export type BetterAuthPluginById<
	A extends BetterAuthPluginHost,
	Id extends string,
> = [Extract<BetterAuthPluginOf<A>, { id: Id }>] extends [never]
	? BetterAuthPluginOf<A>
	: Extract<BetterAuthPluginOf<A>, { id: Id }>;
