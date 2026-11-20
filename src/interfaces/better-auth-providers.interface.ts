/** What `BetterAuthJwtProvider`'s subclasses pass to `super()`. */
export interface BetterAuthJwtProviderOptions {
	/**
	 * `realm` of the `WWW-Authenticate` challenges: the one sent when no
	 * provider found credentials, and the `invalid_token` one.
	 * @default 'api'
	 */
	realm?: string;
}

/** What `BetterAuthApiKeyProvider`'s subclasses pass to `super()`. */
export interface BetterAuthApiKeyProviderOptions {
	/**
	 * `realm` of the `WWW-Authenticate` challenge.
	 * @default 'api'
	 */
	realm?: string;
	/**
	 * The headers keys are read from: set it to the `apiKey()` plugin's
	 * `apiKeyHeaders` when you changed those.
	 * @default 'x-api-key'
	 */
	headers?: string | string[];
}
