/**
 * Compile-time checks of BetterAuthOAuthProvider's principal type, run by
 * `bun run typecheck` (`tsc`).
 */
import type { AuthenticationResult, JwtClaims } from "@nestjs/authentication";
import { expectTypeOf } from "vitest";
import type { BetterAuthUser } from "../../src/index.ts";
import {
	type BetterAuthOAuthAccessToken,
	BetterAuthOAuthProvider,
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
