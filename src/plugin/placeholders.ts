import { BetterAuthConfigurationError } from "../errors/better-auth-configuration.error.ts";

/** @internal Marks a config callback that a Nest handler is meant to replace. */
export const PLACEHOLDER = Symbol.for("nestjs-better-auth-adapter:placeholder");

/**
 * For a callback Better Auth's types require but a Nest handler provides,
 * like `magicLink({ sendMagicLink })` with a `BetterAuthMagicLinkHandler`,
 * which replaces it at startup: the app fails to start if none does.
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
			throw new BetterAuthConfigurationError(
				"No Nest handler replaced this Better Auth callback. Register the matching handler (e.g. a class extending BetterAuthMagicLinkHandler) in AuthenticationRegistry.",
			);
		},
		{ [PLACEHOLDER]: true },
	);
