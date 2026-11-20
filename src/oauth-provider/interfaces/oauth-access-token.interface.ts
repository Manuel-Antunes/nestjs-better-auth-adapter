/**
 * The claims of a verified OAuth access token, as `@CurrentSession()` sees
 * them: who granted it (`sub`), to which client (`azp`), and what for.
 */
export type BetterAuthOAuthAccessToken = {
	sub: string;
	/** The client the token was issued to. */
	azp: string;
	client_id: string;
	/** The granted scopes, space-separated, as the token carries them. */
	scope?: string;
	/** The granted scopes. */
	scopes: string[];
	/** The session the user granted it from. */
	sid?: string;
	aud?: string | string[];
	iss?: string;
	iat?: number;
	exp?: number;
	[claim: string]: unknown;
};
