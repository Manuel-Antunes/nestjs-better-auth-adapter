import { SetMetadata } from "@nestjs/common";
import { BetterAuthConfigurationError } from "../errors/better-auth-configuration.error.ts";
import type { OAuthScopesDecorator } from "./interfaces/oauth-scopes-decorator.interface.ts";

/** Where `@OAuthScopes()` keeps its scopes: `OAuthScopes.KEY`. */
const OAUTH_SCOPES = Symbol.for("nestjs-better-auth-adapter:oauth-scopes");

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
 * `BetterAuthOAuthProviderModule` fails at startup on a scope that
 * `oauthProvider({ scopes })` doesn't list, as no token could carry it.
 * `OAuthScopes` is also the key `Reflector` reads the scopes by:
 * `reflector.getAllAndOverride<readonly string[] | undefined>(OAuthScopes, [handler, controller])`.
 *
 * @example
 * ```ts
 * @OAuthScopes('read:post')
 * @Get('posts')
 * list(@CurrentUser() user: User) {}
 * ```
 */
export const OAuthScopes: OAuthScopesDecorator = Object.assign(
	(...scopes: string[]): ClassDecorator & MethodDecorator => {
		for (const scope of scopes) {
			if (typeof scope !== "string" || !SCOPE_TOKEN.test(scope))
				throw new BetterAuthConfigurationError(
					`@OAuthScopes(): ${JSON.stringify(scope)} is not a valid OAuth scope.`,
				);
		}
		// Frozen: whoever reads them gets the declaration, not a copy to edit.
		return SetMetadata(OAUTH_SCOPES, Object.freeze([...scopes]));
	},
	{ KEY: OAUTH_SCOPES },
);
