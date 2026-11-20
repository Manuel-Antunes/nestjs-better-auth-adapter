import { BetterAuthConfigurationError } from "../errors/better-auth-configuration.error.ts";
import type { Auth } from "../interfaces/better-auth-module-options.interface.ts";
import { OAUTH_PROVIDER_PLUGIN } from "../oauth/discovery-paths.ts";
import { findPlugin } from "../plugins.ts";
import type { BetterAuthOAuthProviderOptions } from "./interfaces/better-auth-oauth-provider-options.interface.ts";
import type {
	OAuthResourceClient,
	OAuthResourceSettings,
	ResourceClientAuth,
} from "./interfaces/oauth-resource.interface.ts";

/**
 * `BetterAuthOAuthProvider`'s options, checked, with their defaults. Fails
 * at startup on an audience it could not honor, rather than at the first
 * token.
 */
export function resolveOAuthResource(
	provider: string,
	settings: BetterAuthOAuthProviderOptions,
): OAuthResourceSettings {
	let url: URL | undefined;
	try {
		url = new URL(settings?.audience);
	} catch {}
	if (!url || !/^https?:$/.test(url.protocol) || url.hash)
		throw new BetterAuthConfigurationError(
			`${provider}'s audience must be this API's resource identifier, an http(s) URL without a fragment (like 'https://api.example.com'), not ${JSON.stringify(settings?.audience)}.`,
		);

	// RFC 9728 §3.1: the well-known segment goes between the host and the path.
	const path = url.pathname.replace(/\/$/, "");
	const wellKnown = `/.well-known/oauth-protected-resource${path}`;
	return {
		audience: settings.audience,
		metadataPath: settings.resourceMetadata === false ? undefined : wellKnown,
		metadataUrl: `${url.origin}${wellKnown}${url.search}`,
		metadata: settings.resourceMetadata || {},
		checkSession: settings.checkSession ?? true,
		dpopReplayStore: settings.dpopReplayStore,
	};
}

/** Fails at startup when `auth` can't issue the JWT access tokens `provider` verifies. */
export function assertOAuthResourceServer(auth: Auth, provider: string): void {
	const plugin = findPlugin(auth, OAUTH_PROVIDER_PLUGIN);
	if (!plugin)
		throw new BetterAuthConfigurationError(
			`${provider} verifies the access tokens of Better Auth's oauthProvider() plugin: add it to betterAuth({ plugins }), from '@better-auth/oauth-provider'.`,
		);
	if (plugin.options?.disableJwtPlugin)
		throw new BetterAuthConfigurationError(
			`${provider} verifies JWT access tokens, which oauthProvider() can't issue with disableJwtPlugin: remove that option.`,
		);
}

const clients = new WeakMap<object, Promise<OAuthResourceClient>>();

/**
 * `@better-auth/oauth-provider`'s resource client for `auth`: its issuer,
 * and its keys read in-process. Loaded on first use, so the package is only
 * needed by apps that configure `oauthProvider()`.
 */
export function resourceClientOf(auth: Auth): Promise<OAuthResourceClient> {
	let client = clients.get(auth);
	if (!client) {
		// The .catch() on the import() itself also keeps bundlers (esbuild) from
		// failing the build of apps without the package.
		client = import("@better-auth/oauth-provider/resource-client")
			.catch((error: unknown) => {
				throw new BetterAuthConfigurationError(
					"BetterAuthOAuthProvider needs '@better-auth/oauth-provider', which oauthProvider() comes from: install it.",
					{ cause: error },
				);
			})
			.then(({ oauthProviderResourceClient }) =>
				oauthProviderResourceClient(auth as ResourceClientAuth).getActions(),
			);
		clients.set(auth, client);
	}
	return client;
}
