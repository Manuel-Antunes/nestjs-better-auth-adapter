import type { BetterAuthOptions, IsAny } from "better-auth";
import type {
	BetterAuthPluginById,
	BetterAuthPluginHost,
	BetterAuthPluginId,
} from "./better-auth-plugin.interface.ts";

/** Any callback: every function type is one. */
// biome-ignore lint/suspicious/noExplicitAny: a callback's parameters are whatever Better Auth declares
export type BetterAuthCallback = (...args: any[]) => unknown;

/** What `BetterAuthConfigAugmenter` reads of a Better Auth instance. */
export interface BetterAuthConfigHost extends BetterAuthPluginHost {
	/** The context Better Auth builds from its options, whose copy of them its endpoints read. */
	$context: PromiseLike<{ options: object }>;
}

/** The object part of an option's type: what a path can go through. */
type SectionOf<T> = Exclude<
	NonNullable<T>,
	BetterAuthCallback | readonly unknown[]
>;

/** The keys of `S` whose option is a callback (every member of its type a function). */
type CallbackKeys<S> = {
	[K in keyof S & string]-?: [NonNullable<S[K]>] extends [never]
		? never
		: NonNullable<S[K]> extends BetterAuthCallback
			? K
			: never;
}[keyof S & string];

/** How deep a path goes below its first section (`databaseHooks.user.create.before`). */
type Depth = [never, 0, 1, 2, 3];

/**
 * The paths of the callbacks in section `S` (its schema), through the
 * sections `C` (what the instance configures) has.
 */
type PathsIn<S, C, D extends number> = [D] extends [never]
	? never
	:
			| CallbackKeys<S>
			| {
					[K in keyof S & keyof C & string]-?: SectionOf<S[K]> extends object
						? SectionOf<C[K]> extends object
							? `${K}.${PathsIn<SectionOf<S[K]>, SectionOf<C[K]>, Depth[D]>}`
							: never
						: never;
			  }[keyof S & keyof C & string];

/**
 * Top-level options that aren't Better Auth's config but things it calls
 * (a database, a store, a logger), and its plugins, which
 * `BetterAuthConfigAugmenter.plugin()` reaches.
 */
type NotConfig = "database" | "secondaryStorage" | "logger" | "plugins";

/**
 * The paths of Better Auth's callbacks under the sections `C` configures,
 * from `BetterAuthOptions`' schema: `"user.changeEmail.sendChangeEmailConfirmation"`
 * once `user.changeEmail` is configured. Never a top-level option, which
 * Better Auth copies into its context when the instance is created. With
 * options that don't tell (`any`), every section's.
 */
export type BetterAuthCallbackPath<C = BetterAuthOptions> =
	IsAny<C> extends true
		? BetterAuthCallbackPath<BetterAuthOptions>
		: {
				[K in Exclude<
					keyof BetterAuthOptions & keyof C & string,
					NotConfig
				>]-?: SectionOf<BetterAuthOptions[K]> extends object
					? SectionOf<C[K]> extends object
						? `${K}.${PathsIn<SectionOf<BetterAuthOptions[K]>, SectionOf<C[K]>, 3>}`
						: never
					: never;
			}[Exclude<keyof BetterAuthOptions & keyof C & string, NotConfig>];

/** The callback at `path` in `S`, as Better Auth declares it. */
export type BetterAuthCallbackAt<S, P extends string> = IsAny<S> extends true
	? BetterAuthCallback
	: P extends `${infer K}.${infer Rest}`
		? K extends keyof S
			? BetterAuthCallbackAt<SectionOf<S[K]>, Rest>
			: never
		: P extends keyof S
			? Extract<NonNullable<S[P]>, BetterAuthCallback>
			: never;

/** The options of the instance `A`'s type, or `any`'s when it doesn't tell. */
export type BetterAuthConfiguredOptions<A extends BetterAuthPluginHost> =
	A["options"];

/** The options of the plugin `Id` of `A`, as its type declares them. */
export type BetterAuthPluginOptions<
	A extends BetterAuthPluginHost,
	Id extends BetterAuthPluginId<A>,
> = SectionOf<BetterAuthPluginById<A, Id>["options"]>;

/**
 * The paths of the callbacks in a plugin's options `O`, its top level
 * included: a plugin keeps its options object, which its endpoints read.
 */
export type BetterAuthPluginCallbackPath<O> = IsAny<O> extends true
	? string
	: string extends keyof O
		? string
		: PathsIn<O, O, 3>;

/** What `replace()` and `wrap()` take besides the path and the callback. */
export interface BetterAuthAugmentOptions {
	/**
	 * Create the sections of the path that aren't configured, rather than
	 * fail. A callback doesn't turn its feature on (`enabled`): only for
	 * sections without one, like `user` for `user.validateUserInfo`.
	 */
	create: true;
}
