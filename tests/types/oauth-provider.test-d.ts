/**
 * Compile-time checks of BetterAuthOAuthProvider's principal type, and of
 * `OAuthScopes` as a decorator and a `Reflector` key, run by
 * `bun run typecheck` (`tsc`).
 */
import type { AuthenticationResult, JwtClaims } from "@nestjs/authentication";
import type { ExecutionContext } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { expectTypeOf } from "vitest";
import type { BetterAuthUser } from "../../src/index.ts";
import {
	type BetterAuthOAuthAccessToken,
	BetterAuthOAuthProvider,
	OAuthScopes,
} from "../../src/oauth-provider/index.ts";

type Client = { kind: "client"; clientId: string };

// Without a type argument, the user is Better Auth's.
declare const users: BetterAuthOAuthProvider;
expectTypeOf(
	users.authenticate,
).returns.resolves.toEqualTypeOf<AuthenticationResult<
	BetterAuthUser,
	BetterAuthOAuthAccessToken
> | null>();

// With one, the user is either: users keep the default lookup.
declare const callers: BetterAuthOAuthProvider<Client>;
expectTypeOf(
	callers.authenticate,
).returns.resolves.toEqualTypeOf<AuthenticationResult<
	BetterAuthUser | Client,
	BetterAuthOAuthAccessToken
> | null>();

export class AdmitsClients extends BetterAuthOAuthProvider<Client> {
	protected override async validate(claims: JwtClaims) {
		if (this.isClientCredentials(claims))
			return { kind: "client" as const, clientId: String(claims.azp) };
		return super.validate(claims);
	}
}

export class ReturnsOther extends BetterAuthOAuthProvider<Client> {
	// @ts-expect-error: a principal outside BetterAuthUser | Client
	protected override async validate() {
		return { kind: "robot" as const };
	}
}

// OAuthScopes decorates classes and methods, with any number of scopes.
@OAuthScopes("read:post")
class Posts {
	@OAuthScopes()
	list() {}

	@OAuthScopes("read:post", "write:post")
	write() {}
}
// @ts-expect-error scopes are strings
OAuthScopes(1);

// And Reflector reads them by it, as by a key of Reflector.createDecorator().
declare const reflector: Reflector;
declare const context: ExecutionContext;
expectTypeOf(OAuthScopes.KEY).toEqualTypeOf<symbol>();
expectTypeOf(
	reflector.getAllAndOverride<readonly string[] | undefined>(OAuthScopes, [
		context.getHandler(),
		context.getClass(),
	]),
).toEqualTypeOf<readonly string[] | undefined>();
expectTypeOf(
	reflector.get<readonly string[] | undefined>(OAuthScopes, Posts),
).toEqualTypeOf<readonly string[] | undefined>();
