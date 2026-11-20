import { normalizePath } from "@nestjs/common/utils/shared.utils.js";
import { BetterAuthConfigurationError } from "../errors/better-auth-configuration.error.ts";
import {
	type BetterAuthOptions,
	getBaseURL,
	isDynamicBaseURLConfig,
} from "better-auth";

/**
 * Where Better Auth's router expects its routes, resolved as `betterAuth()`
 * resolves them: the path of `baseURL` (the option, or `BETTER_AUTH_URL` and
 * the other environment variables Better Auth reads) when it has one, else
 * `basePath`, `/api/auth` by default. Normalized: one leading slash, no
 * trailing one.
 */
export function resolveBasePath(
	options: Pick<BetterAuthOptions, "baseURL" | "basePath">,
): string {
	const baseURL = isDynamicBaseURLConfig(options.baseURL)
		? undefined
		: getBaseURL(
				typeof options.baseURL === "string" ? options.baseURL : undefined,
				options.basePath,
			);
	const path = normalizePath(
		baseURL ? new URL(baseURL).pathname : options.basePath || "/api/auth",
	);
	if (path === "/")
		throw new BetterAuthConfigurationError(
			"Better Auth's routes need a path of their own: they can't share the root with the app's. Set Better Auth's basePath (or the path of its baseURL), like '/api/auth'.",
		);
	return path;
}
