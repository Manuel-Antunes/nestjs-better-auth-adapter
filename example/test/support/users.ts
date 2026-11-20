import { expect } from "vitest";
import type { TestApp } from "./test-app.ts";
import { totpCode } from "./totp.ts";

export const PASSWORD = "correct-horse-battery-staple";

let counter = 0;
export const uniqueEmail = (prefix = "user") =>
	`${prefix}-${Date.now()}-${counter++}@example.com`;

export interface TestUser {
	id: string;
	email: string;
	name: string;
	/** The session token, sent as `Authorization: Bearer` (bearer() plugin). */
	token: string;
	/** `Authorization` header value. */
	bearer: string;
}

const asUser = (body: {
	token: string;
	user: { id: string; email: string; name: string };
}): TestUser => ({
	id: body.user.id,
	email: body.user.email,
	name: body.user.name,
	token: body.token,
	bearer: `Bearer ${body.token}`,
});

/** Signs up through Better Auth's own route, as a client would. */
export async function signUp(
	t: TestApp,
	options: { email?: string; name?: string } = {},
): Promise<TestUser> {
	const response = await t
		.http()
		.post("/api/auth/sign-up/email")
		.send({
			name: options.name ?? "Test User",
			email: options.email ?? uniqueEmail(),
			password: PASSWORD,
		})
		.expect(200);
	return asUser(response.body);
}

/** The `?token=` of the link to the frontend page that was mailed to `to`. */
export function mailedToken(t: TestApp, to: string, subject: RegExp): string {
	const token = new URL(t.mailer.link(to, subject)).searchParams.get("token");
	if (!token) throw new Error(`No token in the link mailed to ${to}`);
	return token;
}

/**
 * Does what the frontend's verification page does with the link the
 * EmailVerificationHandler mailed: hands its token to Better Auth.
 */
export async function verifyEmail(t: TestApp, user: TestUser) {
	const token = mailedToken(t, user.email, /Verify your/);
	await t.http().get("/api/auth/verify-email").query({ token }).expect(200);
}

export async function signUpVerified(
	t: TestApp,
	options: { email?: string; name?: string } = {},
) {
	const user = await signUp(t, options);
	await verifyEmail(t, user);
	return user;
}

/**
 * Sets the platform role. The first admin of a real deployment comes from a
 * seed script the same way; later ones from `POST /api/auth/admin/set-role`.
 */
export async function setRole(t: TestApp, user: TestUser, role: string) {
	const ctx = await t.auth.$context;
	await ctx.internalAdapter.updateUser(user.id, { role });
}

/**
 * Enrolls an authenticator (enable, then confirm with a TOTP code), then
 * steps the current session up with a backup code: enrolling alone doesn't
 * satisfy `@Authenticate({ mfa: true })`, nor the sensitive routes' hook.
 */
export async function enrollAndStepUp(t: TestApp, user: TestUser) {
	const enabled = await t
		.http()
		.post("/api/auth/two-factor/enable")
		.set("Authorization", user.bearer)
		.send({ password: PASSWORD })
		.expect(200);
	const { totpURI, backupCodes } = enabled.body as {
		totpURI: string;
		backupCodes: string[];
	};

	const confirmed = await t
		.http()
		.post("/api/auth/two-factor/verify-totp")
		.set("Authorization", user.bearer)
		.send({ code: totpCode(totpURI) })
		.expect(200);
	adoptRotatedSession(user, confirmed);

	await stepUp(t, user, backupCodes[0]);
	return { totpURI, backupCodes };
}

/** Verifies a second factor on the existing session (step-up). */
export async function stepUp(t: TestApp, user: TestUser, backupCode: string) {
	const response = await t
		.http()
		.post("/api/auth/two-factor/verify-backup-code")
		.set("Authorization", user.bearer)
		.send({ code: backupCode })
		.expect(200);
	adoptRotatedSession(user, response);
}

/**
 * A two-factor verification replaces the session (and revokes the old one).
 * Clients pick up the new token from the `set-auth-token` header (bearer()
 * plugin), as a browser picks up the new cookie.
 */
export function adoptRotatedSession(
	user: TestUser,
	response: { headers: Record<string, unknown> },
) {
	const rotated = response.headers["set-auth-token"];
	if (typeof rotated === "string" && rotated) {
		user.token = rotated;
		user.bearer = `Bearer ${rotated}`;
	}
}

/** Creates an organization through Better Auth; it becomes the session's active one. */
export async function createOrganization(
	t: TestApp,
	owner: TestUser,
	name = "Acme",
) {
	const response = await t
		.http()
		.post("/api/auth/organization/create")
		.set("Authorization", owner.bearer)
		.send({ name, slug: `${name.toLowerCase()}-${Date.now()}-${counter++}` })
		.expect(200);
	return response.body as { id: string; name: string };
}

/** Invites `user` through Better Auth's route, accepts as them, then makes the organization active. */
export async function joinOrganization(
	t: TestApp,
	owner: TestUser,
	user: TestUser,
	organizationId: string,
	role: string,
) {
	const invited = await t
		.http()
		.post("/api/auth/organization/invite-member")
		.set("Authorization", owner.bearer)
		.send({ email: user.email, role, organizationId })
		.expect(200);
	await t
		.http()
		.post("/api/auth/organization/accept-invitation")
		.set("Authorization", user.bearer)
		.send({ invitationId: invited.body.id })
		.expect(200);
	await setActiveOrganization(t, user, organizationId);
}

export async function setActiveOrganization(
	t: TestApp,
	user: TestUser,
	organizationId: string,
) {
	const response = await t
		.http()
		.post("/api/auth/organization/set-active")
		.set("Authorization", user.bearer)
		.send({ organizationId });
	expect(response.status).toBe(200);
}
