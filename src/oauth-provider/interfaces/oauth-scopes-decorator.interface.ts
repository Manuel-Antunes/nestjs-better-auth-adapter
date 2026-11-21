/**
 * `@OAuthScopes()`, which is also the key its scopes are read by, as with
 * the decorators of `Reflector.createDecorator()`:
 *
 * ```ts
 * reflector.getAllAndOverride<readonly string[] | undefined>(OAuthScopes, [
 *   context.getHandler(),
 *   context.getClass(),
 * ]);
 * ```
 */
export interface OAuthScopesDecorator {
	(...scopes: string[]): ClassDecorator & MethodDecorator;
	/** The metadata key of the scopes, which `Reflector` reads when handed `OAuthScopes`. */
	readonly KEY: symbol;
}
