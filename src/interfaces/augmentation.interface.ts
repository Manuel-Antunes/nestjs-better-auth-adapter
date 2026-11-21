import type { BetterAuthCallback } from "./better-auth-config-augmenter.interface.ts";

/** @internal A change `BetterAuthConfigAugmenter` queued, applied in order. */
export interface Augmentation {
	/** The plugin whose options it changes: Better Auth's own options without. */
	plugin?: string;
	/** The path as given, for the errors and the logs. */
	path: string;
	/** The sections the callback is in, from the options (or the plugin's). */
	sections: string[];
	/** The callback's key in the last section. */
	key: string;
	/** The callback to set, from the one there. */
	callback: (original: BetterAuthCallback | undefined) => BetterAuthCallback;
	/** Whether it replaces the callback there (logged), rather than wrap it. */
	replaces: boolean;
	/** Create the sections that aren't configured. */
	create: boolean;
}

/** @internal What `restore()` puts back for one applied change. */
export interface AppliedAugmentation {
	/** The callbacks set: each section, and what its key held. */
	leaves: {
		section: Record<string, unknown>;
		key: string;
		had: boolean;
		previous: unknown;
	}[];
	/** The sections created, outermost first. */
	created: { section: Record<string, unknown>; key: string }[];
}
