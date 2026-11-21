import { SetMetadata } from "@nestjs/common";
import { BetterAuthConfigurationError } from "../errors/better-auth-configuration.error.ts";
import type { OAuthScopesDecorator } from "./interfaces/oauth-scopes-decorator.interface.ts";

/** Where `@OAuthScopes.require()` and `.any()` keep their scopes: `OAuthScopes.KEY`. */
const OAUTH_SCOPES = Symbol.for("nestjs-better-auth-adapter:oauth-scopes");

/** A scope token, as RFC 6749 §3.3 allows them. */
const SCOPE_TOKEN = /^[\x21\x23-\x5b\x5d-\x7e]+$/;

function declare(
	decorator: string,
	scopes: readonly string[],
): ClassDecorator & MethodDecorator {
	for (const scope of scopes) {
		if (typeof scope !== "string" || !SCOPE_TOKEN.test(scope))
			throw new BetterAuthConfigurationError(
				`${decorator}: ${JSON.stringify(scope)} is not a valid OAuth scope.`,
			);
	}
	// Frozen: whoever reads them gets the declaration, not a copy to edit.
	return SetMetadata(OAUTH_SCOPES, Object.freeze([...scopes]));
}

function requireScopes(...scopes: string[]): ClassDecorator & MethodDecorator {
	if (scopes.length === 0)
		throw new BetterAuthConfigurationError(
			"@OAuthScopes.require() needs a scope: @OAuthScopes.any() accepts any access token issued for this API.",
		);
	return declare("@OAuthScopes.require()", scopes);
}

function anyScopes(): ClassDecorator & MethodDecorator {
	return declare("@OAuthScopes.any()", []);
}

/**
 * Lets OAuth access tokens (`BetterAuthOAuthProvider`) authenticate a
 * route, or every route of a controller:
 *
 * - `@OAuthScopes.require('read:post', ...)`: tokens carrying every one of
 *   these scopes. A token missing one gets a 403 with RFC 6750's
 *   `insufficient_scope` challenge, naming them.
 * - `@OAuthScopes.any()`: any token issued for this API, with no scope
 *   required (a route that checks its scopes another way).
 *
 * Routes without either refuse access tokens with a 403: a token a user
 * granted to another app stays limited to what they consented to. A
 * `BetterAuthOAuthProvider` subclass can decide otherwise in `scopesFor()`.
 * The other credentials (the session, `jwt()` JWTs, API keys) are not
 * affected. A method's declaration replaces its controller's.
 *
 * `BetterAuthOAuthProviderModule` fails at startup on a scope that
 * `oauthProvider({ scopes })` doesn't list, as no token could carry it.
 * `OAuthScopes` is also the key `Reflector` reads the scopes by (`[]` for
 * `any()`):
 * `reflector.getAllAndOverride<readonly string[] | undefined>(OAuthScopes, [handler, controller])`.
 *
 * @example
 * ```ts
 * @OAuthScopes.require('read:post')
 * @Get('posts')
 * list(@CurrentUser() user: User) {}
 * ```
 */
export const OAuthScopes: OAuthScopesDecorator = Object.freeze({
	KEY: OAUTH_SCOPES,
	require: requireScopes,
	any: anyScopes,
});
