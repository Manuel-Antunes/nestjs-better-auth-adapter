import type { oauthProviderResourceClient } from "@better-auth/oauth-provider/resource-client";
import type { DpopReplayStore } from "better-auth/oauth2";

/** One of the resource identifiers a `BetterAuthOAuthProvider` accepts tokens for. */
export interface OAuthResourceIdentifier {
	audience: string;
	/** Its URL's path, without a trailing slash: matched against the request's. */
	path: string;
	/** Where its RFC 9728 metadata is served, if it is. */
	metadataPath?: string;
	/** Its absolute URL, for `WWW-Authenticate`'s `resource_metadata`. */
	metadataUrl: string;
}

/** `BetterAuthOAuthProvider`'s options, checked, with their defaults. */
export interface OAuthResourceSettings {
	/** Its audiences, in the order given: the first is the default. */
	resources: readonly [OAuthResourceIdentifier, ...OAuthResourceIdentifier[]];
	metadata: Record<string, unknown>;
	checkSession: boolean;
	dpopReplayStore?: DpopReplayStore;
}

/** The Better Auth instance the resource client reads its issuer and keys from. */
export type ResourceClientAuth = NonNullable<
	Parameters<typeof oauthProviderResourceClient>[0]
>;

/** `@better-auth/oauth-provider`'s resource client, bound to an instance. */
export type OAuthResourceClient = ReturnType<
	ReturnType<
		typeof oauthProviderResourceClient<ResourceClientAuth>
	>["getActions"]
>;
