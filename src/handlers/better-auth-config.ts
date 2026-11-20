import { Logger } from "@nestjs/common";
import { BetterAuthConfigurationError } from "../errors/better-auth-configuration.error.ts";
import type { ConfigObject } from "../interfaces/handlers.interface.ts";
import { PLACEHOLDER } from "../plugin/placeholders.ts";

const logger = new Logger("BetterAuthModule");

/** A date `seconds` from now, for the links Better Auth hands to a callback. */
export const expiresIn = (seconds: number): Date =>
	new Date(Date.now() + seconds * 1000);

/** The `options[key]` object a handler plugs into: it must be configured. */
export function configSection(
	options: ConfigObject,
	key: string,
	feature: string,
	example: string,
): ConfigObject {
	const section = options[key];
	if (typeof section !== "object" || section === null)
		throw new BetterAuthConfigurationError(
			`A ${feature} handler is registered but Better Auth's '${key}' is not configured. Add '${example}' to your betterAuth(...) options.`,
		);
	return section;
}

/**
 * Replaces the Better Auth callback `parent[key]` (at `path`, for the logs),
 * saying so when it overrides one the config defines: replaced, not chained,
 * as chaining would send two emails. Returns what puts the original back.
 */
export function replaceCallback(
	parent: ConfigObject,
	path: string,
	callback: (...args: never[]) => unknown,
): () => void {
	const key = path.slice(path.lastIndexOf(".") + 1);
	const original = parent[key];
	if (typeof original === "function" && !original[PLACEHOLDER]) {
		logger.log(`A Nest handler replaces the '${path}' callback.`);
	}
	parent[key] = callback;
	return () => {
		parent[key] = original;
	};
}
