import type { Auth } from "../interfaces/better-auth-module-options.interface.ts";
import { findPlugin } from "../plugins.ts";

export const OAUTH_PROVIDER_PLUGIN = "oauth-provider";

/**
 * The paths outside Better Auth's base path where `oauthProvider()` answers
 * its discovery documents itself, which `BetterAuthModule` forwards to
 * Better Auth's handler as well: RFC 8414's
 * `/.well-known/oauth-authorization-server{issuer path}` always, and the
 * issuer's own documents when a `jwt()` issuer puts them elsewhere. None
 * without the plugin.
 */
export function oauthDiscoveryPaths(auth: Auth, basePath: string): string[] {
	const plugin = findPlugin(auth, OAUTH_PROVIDER_PLUGIN);
	if (!plugin) return [];

	// The plugin's issuer: the jwt() plugin's, else Better Auth's base URL,
	// whose path is the base path.
	const issuer = plugin.options?.disableJwtPlugin
		? undefined
		: (findPlugin(auth, "jwt")?.options?.jwt as { issuer?: string } | undefined)
				?.issuer;
	let issuerPath = basePath;
	if (issuer) {
		try {
			issuerPath = new URL(issuer).pathname.replace(/\/$/, "");
		} catch {}
	}

	return [
		`/.well-known/oauth-authorization-server${issuerPath}`,
		`${issuerPath}/.well-known/oauth-authorization-server`,
		`${issuerPath}/.well-known/openid-configuration`,
	].filter((path) => path !== basePath && !path.startsWith(`${basePath}/`));
}
