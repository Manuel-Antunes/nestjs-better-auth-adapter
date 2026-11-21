/**
 * Compile-time checks of `BetterAuthConfigAugmenter`: its paths and
 * callbacks, typed from the instance. Run by `bun run typecheck` (`tsc`).
 */
import type { GenericEndpointContext } from "better-auth";
import { betterAuth } from "better-auth";
import { jwt } from "better-auth/plugins/jwt";
import { magicLink } from "better-auth/plugins/magic-link";
import { expectTypeOf } from "vitest";
import {
	type Auth,
	BetterAuthConfigAugmenter,
	type BetterAuthCallbackPath,
} from "../../src/index.ts";

const auth = betterAuth({
	emailVerification: {},
	user: { changeEmail: { enabled: true } },
	plugins: [magicLink({ sendMagicLink: async () => {} }), jwt()],
});
const config = new BetterAuthConfigAugmenter(auth);

// The paths: the callbacks of the sections the instance configures.
expectTypeOf<
	"user.changeEmail.sendChangeEmailConfirmation" | "user.validateUserInfo"
>().toExtend<BetterAuthCallbackPath<typeof auth.options>>();

// Each callback takes the signature Better Auth declares.
config.replace(
	"user.changeEmail.sendChangeEmailConfirmation",
	async (data, request) => {
		expectTypeOf(data.newEmail).toEqualTypeOf<string>();
		expectTypeOf(data.url).toEqualTypeOf<string>();
		expectTypeOf(data.user.email).toEqualTypeOf<string>();
		expectTypeOf(request).toEqualTypeOf<Request | undefined>();
	},
);
config.replace(
	"emailVerification.sendVerificationEmail",
	async ({ user, token }) => {
		expectTypeOf(user.id).toEqualTypeOf<string>();
		expectTypeOf(token).toEqualTypeOf<string>();
	},
);
config.replace(
	"user.changeEmail.sendChangeEmailConfirmation",
	// @ts-expect-error a callback of another signature
	(data: { phone: number }) => data.phone,
);

// A section the instance doesn't configure: refused, unless created.
config.replace(
	// @ts-expect-error user.deleteUser isn't configured
	"user.deleteUser.sendDeleteAccountVerification",
	async () => {},
);
config.replace(
	"user.deleteUser.sendDeleteAccountVerification",
	async ({ user, url }) => {
		expectTypeOf(user.id).toEqualTypeOf<string>();
		expectTypeOf(url).toEqualTypeOf<string>();
	},
	{ create: true },
);

// Never a top-level option, nor something that isn't a callback.
// @ts-expect-error a top-level option
config.replace("onAPIError", async () => {});
// @ts-expect-error not a callback
config.replace("user.changeEmail.enabled", async () => {});
// @ts-expect-error not an option
config.replace("user.changeEmail.sendSomethingElse", async () => {});

// wrap() hands the callback there, if any, and returns one of its signature.
config.wrap("user.validateUserInfo", (original) => {
	expectTypeOf(original).toExtend<
		((...args: never[]) => unknown) | undefined
	>();
	return async (data, context) => {
		expectTypeOf(context).toEqualTypeOf<GenericEndpointContext>();
		return original?.(data, context);
	};
});

// A plugin's callbacks, typed as the plugin declares them.
config.plugin("magic-link", (plugin) =>
	plugin.replace("sendMagicLink", async (data, context) => {
		expectTypeOf(data.email).toEqualTypeOf<string>();
		expectTypeOf(data.metadata).toEqualTypeOf<
			// biome-ignore lint/suspicious/noExplicitAny: as magicLink() declares it
			Record<string, any> | undefined
		>();
		expectTypeOf(context).toEqualTypeOf<GenericEndpointContext | undefined>();
	}),
);
config.plugin("magic-link", (plugin) =>
	// @ts-expect-error not one of the plugin's callbacks
	plugin.replace("sendSomethingElse", async () => {}),
);
// @ts-expect-error admin() isn't one of the instance's plugins
config.plugin("admin", () => {});

// The calls chain, in order.
expectTypeOf(
	config
		.replace("user.validateUserInfo", async () => undefined)
		.plugin("magic-link", () => {}),
).toEqualTypeOf<BetterAuthConfigAugmenter<typeof auth>>();
expectTypeOf(config.apply()).resolves.toEqualTypeOf<
	BetterAuthConfigAugmenter<typeof auth>
>();

// With an instance whose type doesn't tell (Auth), every section's callback,
// still typed by Better Auth's schema.
declare const untyped: Auth;
new BetterAuthConfigAugmenter(untyped).replace(
	"user.deleteUser.sendDeleteAccountVerification",
	async ({ user }) => {
		expectTypeOf(user.email).toEqualTypeOf<string>();
	},
);
// @ts-expect-error still only Better Auth's callbacks
new BetterAuthConfigAugmenter(untyped).replace("user.nope", async () => {});
