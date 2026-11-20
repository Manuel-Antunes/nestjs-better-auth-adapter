import type { oauthProviderResourceClient } from "@better-auth/oauth-provider/resource-client";
import type { DpopReplayStore } from "better-auth/oauth2";

/** `BetterAuthOAuthProvider`'s options, checked, with their defaults. */
export interface OAuthResourceSettings {
	audience: string;
	/** Where the RFC 9728 metadata is served, if it is. */
	metadataPath?: string;
	/** Its absolute URL, for `WWW-Authenticate`'s `resource_metadata`. */
	metadataUrl: string;
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
