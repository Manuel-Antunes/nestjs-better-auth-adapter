import type { ServerResponse } from "node:http";
import { BetterAuthConfigurationError } from "../errors/better-auth-configuration.error.ts";
import type { Auth } from "../interfaces/better-auth-module-options.interface.ts";
import { findPlugin } from "../plugins.ts";

/**
 * The policy `@better-auth/oauth-provider` sends with its discovery
 * documents: the JWKS they point at gets the same.
 */
export const DEFAULT_JWKS_CACHE_CONTROL =
	"public, max-age=15, stale-while-revalidate=15, stale-if-error=86400";

/** A header value: visible ASCII, spaces and tabs, so no header injection. */
const HEADER_VALUE = /^[\t\x20-\x7e]+$/;

/**
 * Where the `jwt()` plugin serves its JWKS (`jwks.jwksPath`, under the base
 * path), and the `Cache-Control` `BetterAuthModule` sends with it: `option`,
 * else the default. None without `jwt()`, with its `jwks.remoteUrl` (the
 * JWKS is published there, and Better Auth answers a 404 here), or with
 * `false`.
 */
export function resolveJwksCacheControl(
	auth: Auth,
	basePath: string,
	option: unknown,
): { path: string; cacheControl: string } | undefined {
	if (
		option !== undefined &&
		option !== false &&
		!(
			typeof option === "string" &&
			option.trim() !== "" &&
			HEADER_VALUE.test(option)
		)
	)
		throw new BetterAuthConfigurationError(
			`BetterAuthModule's jwksCacheControl must be a Cache-Control header value (like '${DEFAULT_JWKS_CACHE_CONTROL}'), or false, not ${JSON.stringify(option)}.`,
		);

	const plugin = findPlugin(auth, "jwt");
	if (!plugin) {
		// A policy for a document no one serves: a misconfiguration to show.
		if (typeof option === "string")
			throw new BetterAuthConfigurationError(
				"BetterAuthModule's jwksCacheControl is for the JWKS of Better Auth's jwt() plugin, which isn't configured: add it, or remove jwksCacheControl.",
			);
		return undefined;
	}
	const jwks = plugin.options?.jwks as
		| { jwksPath?: unknown; remoteUrl?: unknown }
		| undefined;
	if (jwks?.remoteUrl) {
		if (typeof option === "string")
			throw new BetterAuthConfigurationError(
				`BetterAuthModule's jwksCacheControl is for the JWKS Better Auth serves, but jwt() publishes it at its jwks.remoteUrl (${String(jwks.remoteUrl)}): remove jwksCacheControl, and send the header where the JWKS is served.`,
			);
		return undefined;
	}
	if (option === false) return undefined;

	// jwt() itself refuses a jwksPath that isn't a path.
	const jwksPath = jwks?.jwksPath;
	return {
		path: `${basePath}${typeof jwksPath === "string" ? jwksPath : "/jwks"}`,
		cacheControl: option ?? DEFAULT_JWKS_CACHE_CONTROL,
	};
}

/**
 * Sends `cacheControl` with `res` if it is a 200 without a `Cache-Control`
 * of its own: what Better Auth sends wins, and an error is never cached.
 * Through `writeHead()`, which Node calls for an implicit head too.
 */
export function fillCacheControl(
	res: ServerResponse,
	cacheControl: string,
): void {
	const writeHead = res.writeHead;
	res.writeHead = function (this: ServerResponse, ...args: unknown[]) {
		res.writeHead = writeHead;
		if (args[0] === 200 && !this.hasHeader("cache-control"))
			this.setHeader("Cache-Control", cacheControl);
		return (writeHead as (...args: unknown[]) => ServerResponse).apply(
			this,
			args,
		);
	} as ServerResponse["writeHead"];
}
