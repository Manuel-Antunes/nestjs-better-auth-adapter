/** @internal Marks a config callback that a Nest handler is meant to replace. */
export const PLACEHOLDER = Symbol.for("nestjs-better-auth-adapter:placeholder");

/**
 * For a callback Better Auth's types require but a Nest handler provides,
 * like `magicLink({ sendMagicLink })` with a `MagicLinkHandler`.
 * `BetterAuthModule` replaces it at startup, and fails if no handler exists.
 *
 * @example
 * ```ts
 * magicLink({ sendMagicLink: fromNestHandler })
 * ```
 */
// biome-ignore lint/suspicious/noExplicitAny: stands in for callbacks of any signature
export const fromNestHandler: (...args: any[]) => Promise<never> =
	Object.assign(
		async () => {
			throw new Error(
				"No Nest handler replaced this Better Auth callback. Provide the matching handler (e.g. a class extending MagicLinkHandler) in one of your modules.",
			);
		},
		{ [PLACEHOLDER]: true },
	);
