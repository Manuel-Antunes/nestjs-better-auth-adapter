import type { MfaState } from "@nestjs/authentication";
import { createAuthMiddleware, isAPIError } from "better-auth/api";
import { addDatabaseHook } from "../hooks/database-hooks.ts";
import type {
	AuthHookContext,
	BridgeHook,
	NestBridge,
} from "./interfaces/bridge.interface.ts";
import type {
	EventPublisher,
	EventSession,
	EventSnapshot,
} from "./interfaces/events.interface.ts";
import type { TwoFactorPlugin } from "./interfaces/nestjs-plugin-options.interface.ts";
import {
	CHALLENGED_SIGN_IN_PATHS,
	twoFactorStateOf,
} from "./two-factor-state.ts";

/*
 * Better Auth's flows, published as @nestjs/authentication's events. Each
 * request's state is keyed by its `ctx.context`, which Better Auth creates
 * for each endpoint call and passes to its hooks and database hooks: nothing
 * outlives the request.
 */

/** What the before hooks read, for the after hook. */
const snapshots = new WeakMap<object, EventSnapshot>();
/** The session a request created, from the `session` create hook. */
const createdSessions = new WeakMap<
	object,
	{ userId: string; sessionId: string }
>();
/** Requests whose user update marks the address verified. */
const verifyingEmail = new WeakSet<object>();

/** Codes the `twoFactor()` verifications answer a refused code with. */
const REFUSED_CODES = new Set([
	"INVALID_CODE",
	"INVALID_BACKUP_CODE",
	"ACCOUNT_TEMPORARILY_LOCKED",
	"TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE",
]);
/** The ones that mean no more codes are taken for now. */
const LOCKED_CODES = new Set([
	"ACCOUNT_TEMPORARILY_LOCKED",
	"TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE",
]);

/** The sign-in methods of the routes that don't say it in their path. */
const SIGN_IN_METHODS: Record<string, string> = {
	"/sign-in/email": "password",
	"/sign-up/email": "password",
	"/sign-in/username": "password",
	"/sign-in/phone-number": "password",
	"/magic-link/verify": "magic-link",
	"/email-otp/verify-email": "email-otp",
	"/phone-number/verify": "phone-otp",
	"/verify-email": "email-verification",
	"/one-tap/callback": "oidc:google",
	"/passkey/verify-authentication": "passkey",
	"/admin/impersonate-user": "impersonation",
};

const bodyOf = (ctx: AuthHookContext) =>
	(ctx.body ?? {}) as Record<string, unknown>;

/** Whether the endpoint answered without an error: a redirect counts. */
function succeeded(ctx: AuthHookContext): boolean {
	const returned = ctx.context.returned;
	return !isAPIError(returned) || returned.statusCode < 400;
}

/** The code of the endpoint's error, if it failed. */
function errorCode(ctx: AuthHookContext): string | undefined {
	const returned = ctx.context.returned;
	if (!isAPIError(returned)) return undefined;
	return (returned.body as { code?: unknown } | undefined)?.code as
		| string
		| undefined;
}

/**
 * A request that creates a session for someone who already has one: it
 * replaces it, and is no sign-in. A two-factor verification completes the
 * sign-in its challenge published.
 */
const isRotation = (path: string) =>
	path.startsWith("/two-factor/") ||
	path === "/change-password" ||
	path === "/admin/stop-impersonating";

/** How the user proved who they are, as `SignInService.signIn()` takes it. */
function signInMethod(ctx: AuthHookContext): string | undefined {
	const path = ctx.path ?? "";
	if (SIGN_IN_METHODS[path]) return SIGN_IN_METHODS[path];
	if (path === "/sign-in/social") {
		const provider = bodyOf(ctx).provider;
		return typeof provider === "string" ? `oidc:${provider}` : undefined;
	}
	const params = (ctx.params ?? {}) as Record<string, unknown>;
	const provider = params.id ?? params.providerId;
	if (typeof provider === "string" && path.includes("callback"))
		return `${path.startsWith("/sso/") ? "sso" : "oidc"}:${provider}`;
	if (path.startsWith("/sign-in/")) return path.slice("/sign-in/".length);
	return undefined;
}

/** `pending` while `twoFactor()` challenges the sign-in; `verified` for a trusted device. */
async function signInMfa(ctx: AuthHookContext): Promise<MfaState | undefined> {
	const returned = ctx.context.returned as
		| { twoFactorRedirect?: unknown }
		| undefined;
	if (returned?.twoFactorRedirect === true) return "pending";
	if (!CHALLENGED_SIGN_IN_PATHS.has(ctx.path ?? "")) return undefined;
	if (!ctx.context.newSession?.user.twoFactorEnabled) return undefined;
	const twoFactor = ctx.context.getPlugin("two-factor") as
		| TwoFactorPlugin
		| null
		| undefined;
	if (!twoFactor?.shouldRequireTwoFactor) return undefined;
	// Answered from what the request carries, before or after twoFactor()'s
	// own hook, which then replaces the session with a challenge.
	return (await twoFactor.shouldRequireTwoFactor(ctx)) ? "pending" : "verified";
}

/** The session of a token, if it is one. */
async function sessionOf(
	ctx: AuthHookContext,
	token: unknown,
): Promise<EventSession | null> {
	if (typeof token !== "string" || !token) return null;
	const found = await ctx.context.internalAdapter.findSession(token);
	if (!found) return null;
	return { userId: found.session.userId, sessionId: found.session.id, token };
}

/**
 * The session the request carries: its cookie, or a Bearer session token,
 * which the bearer() plugin turns into a cookie only after the before hooks.
 */
async function requestSession(
	ctx: AuthHookContext,
): Promise<EventSession | null> {
	const cookie = await ctx.getSignedCookie(
		ctx.context.authCookies.sessionToken.name,
		ctx.context.secret,
	);
	const bearer = /^Bearer\s+(\S+)$/i.exec(
		ctx.headers?.get("authorization") ?? "",
	)?.[1];
	return sessionOf(
		ctx,
		cookie || (bearer && decodeURIComponent(bearer).split(".")[0]),
	);
}

/** Whether each session is gone: the request really ended it. */
async function ended(
	ctx: AuthHookContext,
	sessions: EventSession[] = [],
): Promise<EventSession[]> {
	const still = await Promise.all(
		sessions.map((session) =>
			ctx.context.internalAdapter.findSession(session.token),
		),
	);
	return sessions.filter((_, i) => !still[i]);
}

/** What the before hooks read, by route. */
const SNAPSHOTS: Record<
	string,
	(ctx: AuthHookContext) => Promise<EventSnapshot | undefined>
> = {
	"/sign-out": async (ctx) => {
		const session = await requestSession(ctx);
		return session ? { sessions: [session] } : undefined;
	},
	"/revoke-session": async (ctx) => {
		const session = await sessionOf(ctx, bodyOf(ctx).token);
		return session ? { sessions: [session] } : undefined;
	},
	"/admin/revoke-user-session": async (ctx) => {
		const session = await sessionOf(ctx, bodyOf(ctx).sessionToken);
		return session ? { sessions: [session] } : undefined;
	},
	"/revoke-other-sessions": async (ctx) => {
		const current = await requestSession(ctx);
		if (!current) return undefined;
		const now = new Date();
		const sessions = await ctx.context.internalAdapter.listSessions(
			current.userId,
		);
		return {
			sessions: sessions
				.filter(
					(session) =>
						session.token !== current.token && session.expiresAt > now,
				)
				.map((session) => ({
					userId: session.userId,
					sessionId: session.id,
					token: session.token,
				})),
		};
	},
	"/reset-password": async (ctx) => {
		const query = (ctx.query ?? {}) as Record<string, unknown>;
		const token = bodyOf(ctx).token || query.token;
		if (typeof token !== "string") return undefined;
		const verification =
			await ctx.context.internalAdapter.findVerificationValue(
				`reset-password:${token}`,
			);
		return verification ? { userId: verification.value } : undefined;
	},
};

const signOutOfEach: EventPublisher = async (ctx, emit) => {
	if (!succeeded(ctx)) return;
	const sessions = snapshots.get(ctx.context)?.sessions;
	for (const { userId, sessionId } of await ended(ctx, sessions))
		emit({ type: "sign-out", userId, sessionId });
};

const signOutEverywhere =
	(userIdOf: (ctx: AuthHookContext) => unknown): EventPublisher =>
	(ctx, emit) => {
		const userId = userIdOf(ctx);
		if (succeeded(ctx) && typeof userId === "string")
			emit({ type: "sign-out", userId, everywhere: true });
	};

const passwordResetRequested: EventPublisher = async (ctx, emit) => {
	const email = bodyOf(ctx).email;
	if (!succeeded(ctx) || typeof email !== "string") return;
	const requested = email.trim().toLowerCase();
	const found = await ctx.context.internalAdapter.findUserByEmail(requested);
	emit({
		type: "password-reset-requested",
		email: requested,
		...(found && { userId: found.user.id }),
	});
};

const secondFactor =
	(method: "totp" | "recovery-code"): EventPublisher =>
	async (ctx, emit) => {
		const state = twoFactorStateOf(ctx);
		const userId = state?.userId;
		if (!state || !userId) return;
		if (succeeded(ctx)) {
			if (state.counts) emit({ type: "mfa-verified", userId, method });
			// Better Auth refuses to enroll over a confirmed authenticator:
			// one is never replaced.
			else if (method === "totp" && !state.confirmed)
				emit({ type: "mfa-enabled", userId, replaced: false });
			return;
		}

		const code = errorCode(ctx);
		if (!code || !REFUSED_CODES.has(code)) return;
		// The account lockout counts a sign-in challenge's failures only.
		const authenticator = await ctx.context.adapter.findOne<{
			failedVerificationCount?: number | null;
			lockedUntil?: Date | string | null;
		}>({ model: "twoFactor", where: [{ field: "userId", value: userId }] });
		const lockedUntil = authenticator?.lockedUntil
			? new Date(authenticator.lockedUntil).getTime()
			: 0;
		emit({
			type: "mfa-failed",
			userId,
			method,
			failures: state.signIn
				? Math.max(authenticator?.failedVerificationCount ?? 0, 1)
				: 1,
			locked: LOCKED_CODES.has(code) || lockedUntil > Date.now(),
		});
	};

const twoFactorEnabled: EventPublisher = async (ctx, emit) => {
	const state = twoFactorStateOf(ctx);
	const userId = state?.userId;
	if (!state || !userId || !succeeded(ctx)) return;
	const [user, authenticator] = await Promise.all([
		ctx.context.internalAdapter.findUserById(userId),
		ctx.context.adapter.findOne<{ verified?: boolean }>({
			model: "twoFactor",
			where: [{ field: "userId", value: userId }],
		}),
	]);
	const enabled = !!(user as { twoFactorEnabled?: boolean } | null)
		?.twoFactorEnabled;
	const confirmed = !!authenticator && authenticator.verified !== false;
	if ((!state.enabled && enabled) || (!state.confirmed && confirmed))
		emit({ type: "mfa-enabled", userId, replaced: false });
};

const sessionUserId = (ctx: AuthHookContext) => ctx.context.session?.user.id;

/** What the after hook publishes, by route, besides sign-ins. */
const PUBLISHERS: Record<string, EventPublisher> = {
	"/sign-out": signOutOfEach,
	"/revoke-session": signOutOfEach,
	"/revoke-other-sessions": signOutOfEach,
	"/admin/revoke-user-session": signOutOfEach,
	"/revoke-sessions": signOutEverywhere(sessionUserId),
	"/admin/revoke-user-sessions": signOutEverywhere((ctx) => bodyOf(ctx).userId),
	"/admin/ban-user": signOutEverywhere((ctx) => bodyOf(ctx).userId),

	"/two-factor/verify-totp": secondFactor("totp"),
	"/two-factor/verify-backup-code": secondFactor("recovery-code"),
	"/two-factor/enable": twoFactorEnabled,
	"/two-factor/disable": (ctx, emit) => {
		const userId = sessionUserId(ctx);
		if (succeeded(ctx) && userId) emit({ type: "mfa-disabled", userId });
	},
	"/two-factor/generate-backup-codes": (ctx, emit) => {
		const userId = sessionUserId(ctx);
		const codes = (ctx.context.returned as { backupCodes?: unknown })
			?.backupCodes;
		if (succeeded(ctx) && userId && Array.isArray(codes))
			emit({ type: "recovery-codes-generated", userId, count: codes.length });
	},

	"/request-password-reset": passwordResetRequested,
	"/email-otp/request-password-reset": passwordResetRequested,
	"/forget-password/email-otp": passwordResetRequested,
	"/reset-password": (ctx, emit) => {
		const userId = snapshots.get(ctx.context)?.userId;
		if (succeeded(ctx) && userId) emit({ type: "password-reset", userId });
	},
	"/email-otp/reset-password": async (ctx, emit) => {
		const email = bodyOf(ctx).email;
		if (!succeeded(ctx) || typeof email !== "string") return;
		const found = await ctx.context.internalAdapter.findUserByEmail(
			email.trim().toLowerCase(),
		);
		if (found) emit({ type: "password-reset", userId: found.user.id });
	},

	// Refused links redirect with `?error=`; Better Auth doesn't tell an
	// expired link from an unknown one.
	"/magic-link/verify": (ctx, emit) => {
		const returned = ctx.context.returned;
		if (!isAPIError(returned)) return;
		const location = new Headers(
			returned.headers as ConstructorParameters<typeof Headers>[0],
		).get("location");
		const error = location
			? new URL(location, "http://localhost").searchParams.get("error")
			: null;
		if (!error || error.startsWith("failed_to_")) return;
		emit({
			type: "magic-link-refused",
			reason:
				error === "INVALID_TOKEN"
					? "unknown"
					: error === "EXPIRED_TOKEN"
						? "expired"
						: "refused",
		});
	},
};

/** A sign-in: a session created by anything but a replacement. */
const signedIn: EventPublisher = async (ctx, emit) => {
	const created = createdSessions.get(ctx.context);
	if (!created || isRotation(ctx.path ?? "") || !succeeded(ctx)) return;
	const mfa = await signInMfa(ctx);
	const method = signInMethod(ctx);
	emit({
		type: "sign-in",
		userId: created.userId,
		// A challenged sign-in's session is replaced by the challenge.
		...(mfa !== "pending" && { sessionId: created.sessionId }),
		...(method && { method }),
		...(mfa && { mfa }),
	});
};

/** Logs instead of failing the request: an event is never worth a 500. */
function warn(ctx: AuthHookContext, error: unknown) {
	ctx.context.logger.warn(
		`nestjs(): could not publish the authentication events of ${ctx.path}: ${error instanceof Error ? error.message : String(error)}`,
	);
}

/**
 * The request hooks that publish Better Auth's flows as
 * `AuthenticationEvents`. They match nothing until `BetterAuthModule` binds
 * `bridge.emit`.
 */
export function eventHooks(bridge: NestBridge): {
	before: BridgeHook[];
	after: BridgeHook[];
} {
	return {
		before: [
			{
				matcher: (ctx) => !!bridge.emit && (ctx.path ?? "") in SNAPSHOTS,
				handler: createAuthMiddleware(async (ctx) => {
					try {
						const snapshot = await SNAPSHOTS[ctx.path]?.(ctx);
						if (snapshot) snapshots.set(ctx.context, snapshot);
					} catch (error) {
						warn(ctx, error);
					}
				}),
			},
		],
		after: [
			{
				matcher: () => !!bridge.emit,
				handler: createAuthMiddleware(async (ctx) => {
					const emit = bridge.emit;
					if (!emit) return;
					try {
						await signedIn(ctx, emit);
						await PUBLISHERS[ctx.path]?.(ctx, emit);
					} catch (error) {
						warn(ctx, error);
					}
				}),
			},
		],
	};
}

/** The endpoint context of a database hook's call, if a request made it. */
const endpointOf = (context: unknown) =>
	(context as { context?: object; path?: string } | null | undefined)?.context
		? (context as { context: object; path?: string })
		: undefined;

/**
 * The database hooks the events read: the sessions created (any sign-in,
 * whatever its route), and the users whose address gets verified (a link,
 * an OTP, a provider that vouches for it). Added by `BetterAuthModule` when
 * it binds `bridge.emit`, and taken out with the app's own hooks.
 */
export function addEventDatabaseHooks(bridge: NestBridge): void {
	addDatabaseHook(bridge, "session", "create", "after", (session, context) => {
		const endpoint = endpointOf(context);
		if (endpoint && session?.id)
			createdSessions.set(endpoint.context, {
				userId: session.userId,
				sessionId: session.id,
			});
	});
	// An admin setting the flag proves nothing about the address.
	addDatabaseHook(bridge, "user", "update", "before", (data, context) => {
		const endpoint = endpointOf(context);
		if (
			endpoint &&
			data?.emailVerified === true &&
			!endpoint.path?.startsWith("/admin/")
		)
			verifyingEmail.add(endpoint.context);
	});
	addDatabaseHook(bridge, "user", "update", "after", (user, context) => {
		const endpoint = endpointOf(context);
		if (!endpoint || !verifyingEmail.delete(endpoint.context)) return;
		if (user?.emailVerified && typeof user.email === "string")
			bridge.emit?.({
				type: "email-verified",
				userId: user.id,
				email: user.email,
			});
	});
}
