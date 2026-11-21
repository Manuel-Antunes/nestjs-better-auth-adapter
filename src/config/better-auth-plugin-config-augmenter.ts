import type {
	BetterAuthCallback,
	BetterAuthCallbackAt,
	BetterAuthPluginCallbackPath,
} from "../interfaces/better-auth-config-augmenter.interface.ts";

/** @internal How a plugin's augmenter queues its changes on its `BetterAuthConfigAugmenter`. */
export type QueuePluginChange = (
	path: string,
	callback: (original: BetterAuthCallback | undefined) => BetterAuthCallback,
	replaces: boolean,
) => void;

/**
 * The callbacks of one plugin's options, typed as the plugin declares them
 * (`O`): what `BetterAuthConfigAugmenter.plugin()` hands its function. Its
 * changes join the augmenter's, in the order they're made.
 *
 * @example
 * ```ts
 * config.plugin("magic-link", (magicLink) =>
 *   magicLink.replace("sendMagicLink", async ({ email, url }) => mailer.send(email, url)),
 * );
 * ```
 */
export class BetterAuthPluginConfigAugmenter<O> {
	readonly #queue: QueuePluginChange;

	/** @internal Made by `BetterAuthConfigAugmenter.plugin()`. */
	constructor(queue: QueuePluginChange) {
		this.#queue = queue;
	}

	/** Replaces the plugin's callback at `path`, top level included (`"sendMagicLink"`). */
	replace<const P extends BetterAuthPluginCallbackPath<O>>(
		path: P,
		callback: BetterAuthCallbackAt<O, P>,
	): this {
		this.#queue(path, () => callback as BetterAuthCallback, true);
		return this;
	}

	/**
	 * Replaces the plugin's callback at `path` with what `wrapper` builds
	 * from it (`undefined` when the plugin has none), to run code around it.
	 */
	wrap<const P extends BetterAuthPluginCallbackPath<O>>(
		path: P,
		wrapper: (
			original: BetterAuthCallbackAt<O, P> | undefined,
		) => BetterAuthCallbackAt<O, P>,
	): this {
		this.#queue(
			path,
			(original) =>
				wrapper(original as BetterAuthCallbackAt<O, P>) as BetterAuthCallback,
			false,
		);
		return this;
	}
}
