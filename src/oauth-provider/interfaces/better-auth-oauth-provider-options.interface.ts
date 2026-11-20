import type { DpopReplayStore } from "better-auth/oauth2";

/** What `BetterAuthOAuthProvider`'s subclasses pass to `super()`: this API as a resource server. */
export interface BetterAuthOAuthProviderOptions {
	/**
	 * This API's resource identifier, an http(s) URL: the `resource`
	 * clients request tokens for, which becomes their `aud`. Tokens
	 * for other resources, and those requested without one, are
	 * refused. One of the plugin's `resources`.
	 *
	 * Several, for an API that is the resource server of more than one
	 * identifier: a token passes when its `aud` has any of them. Each gets
	 * its own metadata, and challenges point to the one whose path the
	 * request's path is under (the longest), else the first.
	 */
	audience: string | readonly string[];
	/**
	 * Fields of the RFC 9728 metadata `BetterAuthOAuthProviderModule` serves
	 * at `/.well-known/oauth-protected-resource{audience path}` (such as
	 * `scopes_supported`), one document per audience, which
	 * `WWW-Authenticate` challenges point clients to; `false` to not serve
	 * them.
	 * @default {}
	 */
	resourceMetadata?: Record<string, unknown> | false;
	/**
	 * Refuse a token once the session it was issued from ended (its
	 * `sid`), as introspection does, at the cost of a database
	 * lookup. Otherwise a token passes until it expires.
	 * @default true
	 */
	checkSession?: boolean;
	/**
	 * Where DPoP proofs are recorded so each is used once.
	 * @default Better Auth's storage (`createDpopReplayStore`), shared by every instance
	 */
	dpopReplayStore?: DpopReplayStore;
}
