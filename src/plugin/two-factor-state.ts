import { createAuthMiddleware, getSessionFromCtx } from "better-auth/api";
import type { AuthHookContext } from "./interfaces/bridge.interface.ts";
import type { TwoFactorState } from "./interfaces/two-factor-state.interface.ts";

/** The `twoFactor()` endpoints that verify a second factor. */
export const SECOND_FACTOR_PATHS = new Set([
	"/two-factor/verify-totp",
	"/two-factor/verify-otp",
	"/two-factor/verify-backup-code",
]);

/** The sign-ins `twoFactor()` challenges, unless the device is trusted. */
export const CHALLENGED_SIGN_IN_PATHS = new Set([
	"/sign-in/email",
	"/sign-in/username",
	"/sign-in/phone-number",
]);

/**
 * What each `twoFactor()` request found before its endpoint ran: whether its
 * verification counts as a second factor, and what the events compare with.
 * A verification counts when the user had two-factor enabled and, for TOTP
 * and backup codes, a confirmed authenticator. Confirming a new
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
const states = new WeakMap<object, TwoFactorState>();

/** What {@link recordTwoFactorState} found for this request. */
export const twoFactorStateOf = (
	ctx: AuthHookContext,
): TwoFactorState | undefined => states.get(ctx.context);

/** The user a two-factor request is for: the session's, or the sign-in challenge's. */
async function verifyingUser(
	ctx: AuthHookContext,
): Promise<{ userId?: string; signIn: boolean }> {
	const session = await getSessionFromCtx(ctx).catch(() => null);
	if (session) return { userId: session.user.id, signIn: false };

	// A Bearer session token, when the bearer() plugin hasn't turned it into
	// a cookie yet: its hooks may run after this one.
	const bearer = /^Bearer\s+(\S+)$/i.exec(
		ctx.headers?.get("authorization") ?? "",
	)?.[1];
	if (bearer) {
		const found = await ctx.context.internalAdapter.findSession(
			decodeURIComponent(bearer).split(".")[0],
		);
		if (found) return { userId: found.user.id, signIn: false };
	}

	const challenge = ctx.context.createAuthCookie("two_factor");
	const identifier = await ctx.getSignedCookie(
		challenge.name,
		ctx.context.secret,
	);
	if (!identifier) return { signIn: false };
	const userId = (
		await ctx.context.internalAdapter.findVerificationValue(identifier)
	)?.value;
	return { userId, signIn: !!userId };
}

/** Records the request's {@link TwoFactorState}, before the endpoint changes it. */
export const recordTwoFactorState = createAuthMiddleware(async (ctx) => {
	const { userId, signIn } = await verifyingUser(ctx);
	const user = userId
		? await ctx.context.internalAdapter.findUserById(userId)
		: null;
	const enabled = !!(user as { twoFactorEnabled?: boolean } | null)
		?.twoFactorEnabled;

	// OTP codes go to the user's own channel; TOTP codes and backup codes
	// belong to an authenticator, which must have been confirmed already.
	let confirmed = false;
	if (user && ctx.path !== "/two-factor/verify-otp") {
		const authenticator = await ctx.context.adapter.findOne<{
			verified?: boolean;
		}>({ model: "twoFactor", where: [{ field: "userId", value: user.id }] });
		confirmed = !!authenticator && authenticator.verified !== false;
	}
	states.set(ctx.context, {
		...(user && { userId: user.id }),
		signIn,
		enabled,
		confirmed,
		counts: enabled && (ctx.path === "/two-factor/verify-otp" || confirmed),
	});
});
