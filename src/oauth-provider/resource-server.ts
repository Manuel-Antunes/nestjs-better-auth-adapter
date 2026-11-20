import { BetterAuthConfigurationError } from "../errors/better-auth-configuration.error.ts";
import type { Auth } from "../interfaces/better-auth-module-options.interface.ts";
import { OAUTH_PROVIDER_PLUGIN } from "../oauth/discovery-paths.ts";
import { findPlugin } from "../plugins.ts";
import type { BetterAuthOAuthProviderOptions } from "./interfaces/better-auth-oauth-provider-options.interface.ts";
import type {
	OAuthResourceClient,
	OAuthResourceIdentifier,
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
	const given: unknown = settings?.audience;
	const audiences: unknown[] =
		typeof given === "string" ? [given] : Array.isArray(given) ? given : [];
	if (!audiences.length)
		throw new BetterAuthConfigurationError(
			`${provider}'s audience must be this API's resource identifier, an http(s) URL without a fragment (like 'https://api.example.com'), or a non-empty array of them, not ${JSON.stringify(given)}.`,
		);
	const serve = settings.resourceMetadata !== false;
	const [first, ...others] = audiences.map((audience) =>
		resolveIdentifier(provider, audience, serve),
	);
	const resources = [first, ...others] as OAuthResourceSettings["resources"];

	const listed = new Set<string>();
	/** The audience whose metadata each path serves. */
	const served = new Map<string, string>();
	for (const { audience, metadataPath } of resources) {
		if (listed.has(audience))
			throw new BetterAuthConfigurationError(
				`${provider} lists the audience ${audience} twice.`,
			);
		listed.add(audience);
		if (!metadataPath) continue;
		const other = served.get(metadataPath);
		if (other)
			throw new BetterAuthConfigurationError(
				`${provider}'s audiences ${other} and ${audience} have their resource metadata at the same path, ${metadataPath}, which serves only one: give them different paths, or resourceMetadata: false.`,
			);
		served.set(metadataPath, audience);
	}

	return {
		resources,
		metadata: settings.resourceMetadata || {},
		checkSession: settings.checkSession ?? true,
		dpopReplayStore: settings.dpopReplayStore,
	};
}

function resolveIdentifier(
	provider: string,
	audience: unknown,
	serve: boolean,
): OAuthResourceIdentifier {
	let url: URL | undefined;
	try {
		url = typeof audience === "string" ? new URL(audience) : undefined;
	} catch {}
	if (!url || !/^https?:$/.test(url.protocol) || url.hash)
		throw new BetterAuthConfigurationError(
			`${provider}'s audience must be this API's resource identifier, an http(s) URL without a fragment (like 'https://api.example.com'), not ${JSON.stringify(audience)}.`,
		);

	// RFC 9728 §3.1: the well-known segment goes between the host and the path.
	const path = url.pathname.replace(/\/$/, "");
	const wellKnown = `/.well-known/oauth-protected-resource${path}`;
	return {
		audience: audience as string,
		path,
		metadataPath: serve ? wellKnown : undefined,
		metadataUrl: `${url.origin}${wellKnown}${url.search}`,
	};
}

/**
 * The resource a request at `path` is for: the one whose path `path` is
 * under, the longest when several are, else the first.
 */
export function resourceForPath(
	resources: OAuthResourceSettings["resources"],
	path: string | undefined,
): OAuthResourceIdentifier {
	if (resources.length === 1 || !path) return resources[0];
	let match: OAuthResourceIdentifier | undefined;
	for (const resource of resources) {
		const under =
			resource.path === "" ||
			path === resource.path ||
			path.startsWith(`${resource.path}/`);
		if (under && (!match || resource.path.length > match.path.length))
			match = resource;
	}
	return match ?? resources[0];
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
