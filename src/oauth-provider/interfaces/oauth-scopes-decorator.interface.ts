/**
 * `@OAuthScopes.require()` and `@OAuthScopes.any()`. `OAuthScopes` is also
 * the key their scopes are read by, as with the decorators of
 * `Reflector.createDecorator()`:
 *
 * ```ts
 * reflector.getAllAndOverride<readonly string[] | undefined>(OAuthScopes, [
 *   context.getHandler(),
 *   context.getClass(),
 * ]);
 * ```
 */
export interface OAuthScopesDecorator {
	/**
	 * Accepts access tokens carrying every one of `scopes`; a token missing
	 * one gets a 403 `insufficient_scope`. At least one scope:
	 * {@link OAuthScopesDecorator.any} accepts tokens without.
	 */
	require(scope: string, ...scopes: string[]): ClassDecorator & MethodDecorator;
	/** Accepts any access token issued for this API, with no scope required. */
	any(): ClassDecorator & MethodDecorator;
	/** The metadata key of the scopes, which `Reflector` reads when handed `OAuthScopes`. */
	readonly KEY: symbol;
}
