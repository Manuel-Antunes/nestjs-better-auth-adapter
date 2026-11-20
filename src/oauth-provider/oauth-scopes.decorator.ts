import { SetMetadata } from "@nestjs/common";
import { BetterAuthConfigurationError } from "../errors/better-auth-configuration.error.ts";

export const OAUTH_SCOPES = Symbol.for(
	"nestjs-better-auth-adapter:oauth-scopes",
);

/** A scope token, as RFC 6749 §3.3 allows them. */
const SCOPE_TOKEN = /^[\x21\x23-\x5b\x5d-\x7e]+$/;

/**
 * Lets OAuth access tokens (`BetterAuthOAuthProvider`) authenticate this
 * route, or every route of this controller, when they carry all of
 * `scopes`. A token missing one gets a 403 with RFC 6750's
 * `insufficient_scope` challenge, naming them.
 *
 * Routes without it refuse access tokens with a 403: a token a user granted
 * to another app stays limited to what they consented to. `@OAuthScopes()`
 * with no scope accepts any token issued for this API. The other
 * credentials (the session, `jwt()` JWTs, API keys) are not affected.
 * A method's `@OAuthScopes()` replaces its controller's.
 *
 * @example
 * ```ts
 * @OAuthScopes('read:post')
 * @Get('posts')
 * list(@CurrentUser() user: User) {}
 * ```
 */
export function OAuthScopes(
	...scopes: string[]
): ClassDecorator & MethodDecorator {
	for (const scope of scopes) {
		if (!SCOPE_TOKEN.test(scope))
			throw new BetterAuthConfigurationError(
				`@OAuthScopes(): ${JSON.stringify(scope)} is not a valid OAuth scope.`,
			);
	}
	return SetMetadata(OAUTH_SCOPES, scopes);
}
