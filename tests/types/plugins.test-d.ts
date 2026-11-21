/**
 * Compile-time checks of `findPlugin()` and `hasPlugin()`, typed from the
 * auth instance's own type, run by `bun run typecheck` (`tsc`).
 */
import { betterAuth } from "better-auth";
import { bearer } from "better-auth/plugins/bearer";
import { jwt } from "better-auth/plugins/jwt";
import { magicLink } from "better-auth/plugins/magic-link";
import type { MagicLinkOptions } from "better-auth/plugins/magic-link";
import type { BetterAuthPlugin } from "better-auth";
import { expectTypeOf } from "vitest";
import {
	type Auth,
	type BetterAuthPluginId,
	BetterAuthModule,
	findPlugin,
	hasPlugin,
} from "../../src/index.ts";
import { nestjs } from "../../src/plugin/index.ts";

const auth = betterAuth({
	plugins: [
		bearer(),
		nestjs(),
		jwt({ jwks: { jwksPath: "/.well-known/jwks.json" } }),
		magicLink({ sendMagicLink: async () => {} }),
	],
});

// The ids are the instance's plugins', each its own literal.
expectTypeOf<BetterAuthPluginId<typeof auth>>().toEqualTypeOf<
	"bearer" | "nestjs" | "jwt" | "magic-link"
>();

// A plugin comes back with its own type: its options, as the instance was built.
expectTypeOf(findPlugin(auth, "magic-link")?.options).toEqualTypeOf<
	MagicLinkOptions | undefined
>();
expectTypeOf(findPlugin(auth, "jwt")?.options?.jwks?.jwksPath).toEqualTypeOf<
	string | undefined
>();
expectTypeOf(findPlugin(auth, "jwt")?.id).toEqualTypeOf<"jwt" | undefined>();

// An id the instance doesn't configure is a type error.
// @ts-expect-error admin() isn't one of its plugins
findPlugin(auth, "admin");
// @ts-expect-error nor here
hasPlugin(auth, "admin");
expectTypeOf(hasPlugin(auth, "jwt")).toEqualTypeOf<boolean>();

// Without its plugins in its type (BetterAuthModule's own `Auth`), any id,
// and Better Auth's plugin type.
declare const any: Auth;
expectTypeOf(findPlugin(any, "admin")).toEqualTypeOf<
	BetterAuthPlugin | undefined
>();
declare const wide: Auth<Parameters<typeof betterAuth>[0]>;
expectTypeOf(findPlugin(wide, "admin")).toEqualTypeOf<
	BetterAuthPlugin | undefined
>();

// And `Auth` still takes a concrete instance, as forRoot() needs.
BetterAuthModule.forRoot({ auth });
const asAuth: Auth = auth;
void asAuth;
