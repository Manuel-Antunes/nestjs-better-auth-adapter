/** The claims of a verified JWT, as `@CurrentSession()` sees them. */
export type BetterAuthJwtClaims = {
	sub: string;
	aud: string;
	[claim: string]: unknown;
};
