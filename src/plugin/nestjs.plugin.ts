import type { BetterAuthPlugin } from "better-auth";
import { createAuthMiddleware, isAPIError } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { NEST_BRIDGE } from "./bridge.ts";
import { eventHooks } from "./events.ts";
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
import {
	CHALLENGED_SIGN_IN_PATHS,
	recordTwoFactorState,
	SECOND_FACTOR_PATHS,
	twoFactorStateOf,
} from "./two-factor-state.ts";

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
 * - after a `twoFactor()` verification that counts (`TwoFactorState.counts`), on the
 *   session it created (a sign-in challenge) or the one it was called with
 *   (step-up);
 * - after a challenged sign-in that `twoFactor()` let through because the
 *   device is trusted, which it decides itself, whatever the plugin order.
 */
const markSecondFactor = createAuthMiddleware(async (ctx) => {
	if (isAPIError(ctx.context.returned)) return;
	const newSession = ctx.context.newSession;

	if (SECOND_FACTOR_PATHS.has(ctx.path)) {
		if (!twoFactorStateOf(ctx)?.counts) return;
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
 * - it publishes sign-ins, sign-outs, second-factor changes, password
 *   resets and email verifications as `AuthenticationEvents`;
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
	const events = options.events ?? true;
	const isSecondFactor = (ctx: Parameters<BridgeHook["matcher"]>[0]) =>
		SECOND_FACTOR_PATHS.has(ctx.path ?? "");
	const bridge: NestBridge = {
		hooks: { before: [], after: [] },
		databaseHooks: {},
		events,
	};

	if (mfa || events)
		bridge.hooks.before.push({
			matcher: (ctx) =>
				(mfa && isSecondFactor(ctx)) ||
				(!!bridge.emit &&
					(isSecondFactor(ctx) || ctx.path === "/two-factor/enable")),
			handler: recordTwoFactorState,
		});
	if (mfa)
		bridge.hooks.after.push({
			matcher: (ctx) =>
				isSecondFactor(ctx) || CHALLENGED_SIGN_IN_PATHS.has(ctx.path ?? ""),
			handler: markSecondFactor,
		});
	if (events) {
		const { before, after } = eventHooks(bridge);
		bridge.hooks.before.push(...before);
		bridge.hooks.after.push(...after);
	}

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
