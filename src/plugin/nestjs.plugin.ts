import type { BetterAuthPlugin } from "better-auth";
import {
	createAuthMiddleware,
	getSessionFromCtx,
	isAPIError,
} from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { NEST_BRIDGE } from "./bridge.ts";
import type {
	AuthHookContext,
	BridgeHook,
	NestBridge,
} from "./interfaces/bridge.interface.ts";
import type {
	NestjsPluginOptions,
	TwoFactorPlugin,
} from "./interfaces/nestjs-plugin-options.interface.ts";
import type { BetterAuthPassword } from "./interfaces/password.interface.ts";
import { UPGRADE_HASH } from "./password.constants.ts";

/** The `twoFactor()` endpoints that verify a second factor. */
const SECOND_FACTOR_PATHS = new Set([
	"/two-factor/verify-totp",
	"/two-factor/verify-otp",
	"/two-factor/verify-backup-code",
]);

/** The sign-ins `twoFactor()` challenges, unless the device is trusted. */
const CHALLENGED_SIGN_IN_PATHS = new Set([
	"/sign-in/email",
	"/sign-in/username",
	"/sign-in/phone-number",
]);

/**
 * Whether the request's verification counts as a second factor, decided
 * before the endpoint runs: the user must have had two-factor enabled, and
 * for TOTP and backup codes a confirmed authenticator. Confirming a new
 * authenticator proves nothing about who holds the session: a stolen
 * password-less session could enroll its own.
 *
 * Nothing here outlives a request, so it holds on serverless and with many
 * instances: the key is `ctx.context`, which Better Auth creates for each
 * endpoint call and passes to that call's before and after hooks, and the
 * entry goes with it. What lasts is `mfaVerifiedAt`, in the database. Were
 * the after hook ever to see another context, it would find no entry and
 * mark nothing: a verification gets lost, never invented.
 */
const counts = new WeakMap<object, boolean>();

/** The user a two-factor verification is for: the session's, or the sign-in challenge's. */
async function verifyingUserId(
	ctx: AuthHookContext,
): Promise<string | undefined> {
	const session = await getSessionFromCtx(ctx).catch(() => null);
	if (session) return session.user.id;

	// A Bearer session token, when the bearer() plugin hasn't turned it into
	// a cookie yet: its hooks may run after this one.
	const bearer = /^Bearer\s+(\S+)$/i.exec(
		ctx.headers?.get("authorization") ?? "",
	)?.[1];
	if (bearer) {
		const found = await ctx.context.internalAdapter.findSession(
			decodeURIComponent(bearer).split(".")[0],
		);
		if (found) return found.user.id;
	}

	const challenge = ctx.context.createAuthCookie("two_factor");
	const identifier = await ctx.getSignedCookie(
		challenge.name,
		ctx.context.secret,
	);
	if (!identifier) return undefined;
	return (await ctx.context.internalAdapter.findVerificationValue(identifier))
		?.value;
}

const recordWhetherItCounts = createAuthMiddleware(async (ctx) => {
	const userId = await verifyingUserId(ctx);
	const user = userId
		? await ctx.context.internalAdapter.findUserById(userId)
		: null;
	let verifiedFactor = !!(user as { twoFactorEnabled?: boolean } | null)
		?.twoFactorEnabled;

	// OTP codes go to the user's own channel; TOTP codes and backup codes
	// belong to an authenticator, which must have been confirmed already.
	if (verifiedFactor && userId && ctx.path !== "/two-factor/verify-otp") {
		const authenticator = await ctx.context.adapter.findOne<{
			verified?: boolean;
		}>({ model: "twoFactor", where: [{ field: "userId", value: userId }] });
		verifiedFactor = !!authenticator && authenticator.verified !== false;
	}
	counts.set(ctx.context, verifiedFactor);
});

/** Records on `token`'s session that it passed a second factor. */
async function markVerified(
	ctx: AuthHookContext,
	token: string,
	user?: { id: string },
) {
	const session = await ctx.context.internalAdapter.updateSession(token, {
		mfaVerifiedAt: new Date(),
	});
	if (!session) return;

	// The cookie cache would keep serving the session as it was.
	if (ctx.context.options.session?.cookieCache?.enabled) {
		const owner =
			user ?? (await ctx.context.internalAdapter.findUserById(session.userId));
		if (owner) await setSessionCookie(ctx, { session, user: owner as never });
	}
}

/**
 * Records on the session that its second factor was verified, so
 * `BetterAuthSessionProvider` can report `mfa: 'verified'`:
 * - after a `twoFactor()` verification that counts ({@link counts}), on the
 *   session it created (a sign-in challenge) or the one it was called with
 *   (step-up);
 * - after a challenged sign-in that `twoFactor()` let through because the
 *   device is trusted, which it decides itself, whatever the plugin order.
 */
const markSecondFactor = createAuthMiddleware(async (ctx) => {
	if (isAPIError(ctx.context.returned)) return;
	const newSession = ctx.context.newSession;

	if (SECOND_FACTOR_PATHS.has(ctx.path)) {
		if (!counts.get(ctx.context)) return;
		const token =
			newSession?.session.token ??
			(ctx.context.returned as { token?: unknown } | undefined)?.token;
		if (typeof token === "string")
			await markVerified(ctx, token, newSession?.user);
		return;
	}

	if (!newSession?.user.twoFactorEnabled) return;
	const twoFactor = ctx.context.getPlugin("two-factor") as
		| TwoFactorPlugin
		| null
		| undefined;
	if (!twoFactor?.shouldRequireTwoFactor) return;
	// Answered from what the request carries, before or after twoFactor()'s
	// own hook: a challenged sign-in never counts.
	if (await twoFactor.shouldRequireTwoFactor(ctx)) return;
	await markVerified(ctx, newSession.session.token, newSession.user);
});

/**
 * Connects Better Auth to `BetterAuthModule`. Add it to `plugins`:
 *
 * - `@Hook()` and `@DatabaseHook()` providers run through it, without
 *   `hooks` or `databaseHooks` in the config;
 * - it records a verified second factor on the session (`mfaVerifiedAt`);
 * - it lets `betterAuthPassword()` and `nestPasswordHasher()` upgrade
 *   outdated password hashes.
 *
 * It imports nothing from Nest, so the Better Auth CLI can load the config.
 *
 * @example
 * ```ts
 * betterAuth({ plugins: [twoFactor(), nestjs()] })
 * ```
 */
export function nestjs(options: NestjsPluginOptions = {}) {
	const mfa = options.mfa ?? true;
	const isSecondFactor = (ctx: Parameters<BridgeHook["matcher"]>[0]) =>
		SECOND_FACTOR_PATHS.has(ctx.path ?? "");
	const bridge: NestBridge = {
		hooks: {
			before: mfa
				? [{ matcher: isSecondFactor, handler: recordWhetherItCounts }]
				: [],
			after: mfa
				? [
						{
							matcher: (ctx) =>
								isSecondFactor(ctx) ||
								CHALLENGED_SIGN_IN_PATHS.has(ctx.path ?? ""),
							handler: markSecondFactor,
						},
					]
				: [],
		},
		databaseHooks: {},
	};

	const plugin = {
		id: "nestjs",
		init: (ctx) => {
			const password = ctx.options.emailAndPassword?.password as
				| BetterAuthPassword
				| undefined;
			if (password && UPGRADE_HASH in password) {
				// One conditional write: a hash changed meanwhile (a password
				// reset) is left alone.
				password[UPGRADE_HASH] = async (outdated, upgraded) => {
					try {
						await ctx.adapter.updateMany({
							model: "account",
							where: [
								{ field: "providerId", value: "credential" },
								{ field: "password", value: outdated },
							],
							update: { password: upgraded },
						});
					} catch (error) {
						ctx.logger.warn(
							`Could not upgrade a password hash: ${error instanceof Error ? error.message : String(error)}`,
						);
					}
				};
			}
			return { options: { databaseHooks: bridge.databaseHooks } };
		},
		hooks: bridge.hooks,
		schema: mfa
			? {
					session: {
						fields: {
							mfaVerifiedAt: {
								type: "date",
								required: false,
								input: false,
							},
						},
					},
				}
			: undefined,
	} satisfies BetterAuthPlugin;

	// Not part of the plugin's type: only BetterAuthModule reads it.
	Object.defineProperty(plugin, NEST_BRIDGE, { value: bridge });
	return plugin;
}
