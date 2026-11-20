import { Inject, Injectable } from "@nestjs/common";
import type { AuthenticationResult } from "@nestjs/authentication";
import { APIError } from "better-auth/api";
import { magicLink } from "better-auth/plugins/magic-link";
import { twoFactor } from "better-auth/plugins/two-factor";
import request from "supertest";
import {
	type AuthHookContext,
	BeforeHook,
	BetterAuthService,
	Hook,
} from "../../src/index.ts";
import { nestjs } from "../../src/plugin/index.ts";
import {
	createTestApp,
	createTestAuth,
	signUp,
	type TestAuth,
	uniqueEmail,
} from "../shared/app.ts";

const password = "password-123456";

/** `auth.api` with the plugin endpoints, which `createTestAuth()`'s type doesn't carry. */
// biome-ignore lint/suspicious/noExplicitAny: see above
const api = (auth: TestAuth) => auth.api as any;

/**
 * The cookies a browser holds after `response`, on top of `jar`, as a
 * `Cookie` header value: a later `Set-Cookie` of a name wins, an expired one
 * removes it.
 */
function cookiesAfter(response: request.Response, jar = ""): string {
	const cookies = new Map(
		jar
			.split("; ")
			.filter(Boolean)
			.map((cookie) => [cookie.split("=")[0], cookie] as const),
	);
	const setCookies =
		(response.headers["set-cookie"] as unknown as string[] | undefined) ?? [];
	for (const setCookie of setCookies) {
		const pair = setCookie.split(";")[0];
		const name = pair.split("=")[0];
		if (/max-age=0/i.test(setCookie)) cookies.delete(name);
		else cookies.set(name, pair);
	}
	return [...cookies.values()].join("; ");
}

describe("mfa e2e", () => {
	const magicLinks: string[] = [];
	let auth: TestAuth;
	let setup: Awaited<ReturnType<typeof createTestApp>>;

	beforeAll(async () => {
		auth = createTestAuth({
			baseURL: "http://localhost",
			plugins: [
				// Enabling marks the authenticator verified, so the test needs no TOTP code.
				twoFactor({ skipVerificationOnEnable: true }),
				magicLink({
					sendMagicLink: async ({ url }) => {
						magicLinks.push(url);
					},
				}),
			],
		});
		setup = await createTestApp({ auth });
	});

	afterAll(async () => {
		await setup.app.close();
	});

	const server = () => setup.app.getHttpServer();

	/** A user with two-factor enabled, and their backup codes. */
	async function enrolledUser() {
		const { token, user } = await signUp(auth, { password });
		const { backupCodes } = await api(auth).enableTwoFactor({
			body: { password },
			headers: new Headers({ Authorization: `Bearer ${token}` }),
		});
		return { user, backupCodes };
	}

	/** Signs in with the password: Better Auth answers with a two-factor challenge. */
	async function challenge(email: string) {
		const response = await request(server())
			.post("/api/auth/sign-in/email")
			.send({ email, password })
			.expect(200);
		expect(response.body.twoFactorRedirect).toBe(true);
		return cookiesAfter(response);
	}

	it("verifies a session whose sign-in passed the second factor", async () => {
		const { user, backupCodes } = await enrolledUser();
		const challengeCookie = await challenge(user.email);

		const verified = await request(server())
			.post("/api/auth/two-factor/verify-backup-code")
			.set("Cookie", challengeCookie)
			.send({ code: backupCodes[0] })
			.expect(200);

		await request(server())
			.get("/test/mfa")
			.set("Cookie", cookiesAfter(verified, challengeCookie))
			.expect(200);
	});

	it("verifies a sign-in from a device trusted after a verification", async () => {
		const { user, backupCodes } = await enrolledUser();
		const challengeCookie = await challenge(user.email);
		const verified = await request(server())
			.post("/api/auth/two-factor/verify-backup-code")
			.set("Cookie", challengeCookie)
			.send({ code: backupCodes[0], trustDevice: true })
			.expect(200);
		const trustCookie = cookiesAfter(verified)
			.split("; ")
			.filter((cookie) => cookie.includes("trust_device"))
			.join("; ");
		expect(trustCookie).not.toBe("");

		// twoFactor() lets the trusted device sign in without a challenge.
		const signedIn = await request(server())
			.post("/api/auth/sign-in/email")
			.set("Cookie", trustCookie)
			.send({ email: user.email, password })
			.expect(200);
		expect(signedIn.body.twoFactorRedirect).toBeUndefined();

		await request(server())
			.get("/test/mfa")
			.set("Cookie", cookiesAfter(signedIn))
			.expect(200);
	});

	it("does not verify a session because the user enrolled a second factor", async () => {
		const { user } = await enrolledUser();

		// Magic links are not challenged by twoFactor(): this session has no second factor.
		await api(auth).signInMagicLink({
			body: { email: user.email },
			headers: new Headers(),
		});
		const link = new URL(magicLinks.at(-1) as string);
		const signedIn = await request(server())
			.get(`${link.pathname}${link.search}`)
			.expect(302);

		const response = await request(server())
			.get("/test/mfa")
			.set("Cookie", cookiesAfter(signedIn))
			.expect(401);
		expect(response.body.error).toBe("mfa_required");
	});

	it("verifies the current session when it passes a second factor (step-up)", async () => {
		const { user, backupCodes } = await enrolledUser();
		await api(auth).signInMagicLink({
			body: { email: user.email },
			headers: new Headers(),
		});
		const link = new URL(magicLinks.at(-1) as string);
		const signedIn = await request(server())
			.get(`${link.pathname}${link.search}`)
			.expect(302);
		const sessionCookie = cookiesAfter(signedIn);

		const verified = await request(server())
			.post("/api/auth/two-factor/verify-backup-code")
			.set("Cookie", sessionCookie)
			.send({ code: backupCodes[0] })
			.expect(200);

		// Same session, its cookie cache refreshed with the verification.
		await request(server())
			.get("/test/mfa")
			.set("Cookie", cookiesAfter(verified, sessionCookie))
			.expect(200);
	});

	it("does not verify a session after a wrong code", async () => {
		const { user } = await enrolledUser();
		const challengeCookie = await challenge(user.email);

		const failed = await request(server())
			.post("/api/auth/two-factor/verify-backup-code")
			.set("Cookie", challengeCookie)
			.send({ code: "wrong-code" });
		expect(failed.status).toBeGreaterThanOrEqual(400);

		const sessions = await (await auth.$context).internalAdapter.listSessions(
			user.id,
		);
		expect(
			sessions.filter(
				(session) => (session as { mfaVerifiedAt?: unknown }).mfaVerifiedAt,
			),
		).toHaveLength(0);
	});

	it("does not let clients set mfaVerifiedAt", async () => {
		const { token } = await signUp(auth, { email: uniqueEmail(), password });

		await request(server())
			.post("/api/auth/update-session")
			.set("Authorization", `Bearer ${token}`)
			.send({ mfaVerifiedAt: new Date().toISOString() });

		await request(server())
			.get("/test/mfa")
			.set("Authorization", `Bearer ${token}`)
			.expect(401);
	});
});

describe("mfa e2e: what doesn't count as a second factor", () => {
	/**
	 * Every cookie a response sets, expired ones included: a client that
	 * ignores `Max-Age=0` keeps what a hook set before another expired it.
	 */
	const allCookies = (response: request.Response) =>
		((response.headers["set-cookie"] as unknown as string[] | undefined) ?? [])
			.map((cookie) => cookie.split(";")[0])
			.filter((pair) => !pair.endsWith("="))
			.join("; ");

	it("a challenged password sign-in, whatever the plugin order and the cookie cache", async () => {
		// nestjs() before twoFactor(): its hook runs first.
		const auth = createTestAuth({
			plugins: [nestjs(), twoFactor({ skipVerificationOnEnable: true })],
		});
		expect(auth.options.session?.cookieCache?.enabled).not.toBe(false);
		const { app } = await createTestApp({ auth });

		try {
			const { token, user } = await signUp(auth, { password });
			await api(auth).enableTwoFactor({
				body: { password },
				headers: new Headers({ Authorization: `Bearer ${token}` }),
			});

			const ctx = await auth.$context;
			const updateSession = vi.spyOn(ctx.internalAdapter, "updateSession");

			const signIn = await request(app.getHttpServer())
				.post("/api/auth/sign-in/email")
				.send({ email: user.email, password })
				.expect(200);
			expect(signIn.body.twoFactorRedirect).toBe(true);
			// Not even on the session twoFactor() then deletes.
			expect(
				updateSession.mock.calls.some(
					([, fields]) => (fields as { mfaVerifiedAt?: unknown }).mfaVerifiedAt,
				),
			).toBe(false);
			await request(app.getHttpServer())
				.get("/test/mfa")
				.set("Cookie", allCookies(signIn))
				.expect(401);
			const sessions = await ctx.internalAdapter.listSessions(user.id);
			expect(
				sessions.some(
					(session) => (session as { mfaVerifiedAt?: unknown }).mfaVerifiedAt,
				),
			).toBe(false);
		} finally {
			vi.restoreAllMocks();
			await app.close();
		}
	});

	it("a code of an authenticator being enrolled", async () => {
		// Without skipVerificationOnEnable: enabling leaves the authenticator unconfirmed.
		const auth = createTestAuth({ plugins: [twoFactor()] });
		const { app } = await createTestApp({ auth });

		try {
			const { token } = await signUp(auth, { password });
			const headers = new Headers({ Authorization: `Bearer ${token}` });
			const { backupCodes } = await api(auth).enableTwoFactor({
				body: { password },
				headers,
			});

			// The session that enrolls is a first-factor session, whatever code it shows.
			const verified = await request(app.getHttpServer())
				.post("/api/auth/two-factor/verify-backup-code")
				.set("Authorization", `Bearer ${token}`)
				.send({ code: backupCodes[0] });
			const current =
				(verified.headers["set-auth-token"] as string | undefined) ?? token;

			await request(app.getHttpServer())
				.get("/test/mfa")
				.set("Authorization", `Bearer ${current}`)
				.expect(401);
		} finally {
			await app.close();
		}
	});
});

/** A step-up rule on Better Auth's own routes, as an app writes one. */
@Hook()
@Injectable()
class StepUpHooks {
	/** What `authenticate()` resolved, request after request. */
	readonly seen: (AuthenticationResult | null)[] = [];

	constructor(
		@Inject(BetterAuthService) private readonly betterAuth: BetterAuthService,
	) {}

	@BeforeHook("/revoke-other-sessions")
	async requireSecondFactor(ctx: AuthHookContext) {
		const signedIn = await this.betterAuth.authenticate(ctx);
		this.seen.push(signedIn);
		if (signedIn && signedIn.mfa !== "verified")
			throw new APIError("UNAUTHORIZED", { code: "MFA_REQUIRED" });
	}

	@BeforeHook("/list-sessions")
	async observe(ctx: AuthHookContext) {
		this.seen.push(await this.betterAuth.authenticate(ctx));
	}
}

describe("mfa e2e: BetterAuthService.authenticate() in Better Auth's hooks", () => {
	let auth: TestAuth;
	let setup: Awaited<ReturnType<typeof createTestApp>>;
	let hooks: StepUpHooks;

	beforeAll(async () => {
		auth = createTestAuth({
			plugins: [twoFactor({ skipVerificationOnEnable: true })],
		});
		setup = await createTestApp({ auth, providers: [StepUpHooks] });
		hooks = setup.app.get(StepUpHooks);
	});

	afterAll(async () => {
		vi.restoreAllMocks();
		await setup.app.close();
	});

	const server = () => setup.app.getHttpServer();
	const revokeOthers = (token: string) =>
		request(server())
			.post("/api/auth/revoke-other-sessions")
			.set("Authorization", `Bearer ${token}`)
			.send({});

	it("answers what @Authenticate({ mfa: true }) sees, for a bearer() token too", async () => {
		const signedUp = await signUp(auth, { password });
		const { user } = signedUp;
		// Enabling two-factor replaces the session: the client adopts the new token.
		const enabled = await request(server())
			.post("/api/auth/two-factor/enable")
			.set("Authorization", `Bearer ${signedUp.token}`)
			.send({ password })
			.expect(200);
		const token =
			(enabled.headers["set-auth-token"] as string | undefined) ??
			(signedUp.token as string);
		const { backupCodes } = enabled.body as { backupCodes: string[] };

		const refused = await revokeOthers(token).expect(401);
		expect(refused.body.code).toBe("MFA_REQUIRED");
		expect(hooks.seen.at(-1)).toMatchObject({ user: { id: user.id } });
		expect(hooks.seen.at(-1)?.mfa).toBeUndefined();
		await request(server())
			.get("/test/mfa")
			.set("Authorization", `Bearer ${token}`)
			.expect(401);

		const verified = await request(server())
			.post("/api/auth/two-factor/verify-backup-code")
			.set("Authorization", `Bearer ${token}`)
			.send({ code: backupCodes[0] })
			.expect(200);
		const current = (verified.headers["set-auth-token"] as string) || token;

		await revokeOthers(current).expect(200);
		expect(hooks.seen.at(-1)?.mfa).toBe("verified");
		await request(server())
			.get("/test/mfa")
			.set("Authorization", `Bearer ${current}`)
			.expect(200);
	});

	it("resolves the session once per request: the endpoint reuses it", async () => {
		const { token, user } = await signUp(auth, { password });
		const ctx = await auth.$context;
		const findSession = vi.spyOn(ctx.internalAdapter, "findSession");

		const listed = await request(server())
			.get("/api/auth/list-sessions")
			.set("Authorization", `Bearer ${token}`)
			.expect(200);
		expect(listed.body).toHaveLength(1);
		expect(hooks.seen.at(-1)).toMatchObject({ user: { id: user.id } });
		expect(findSession).toHaveBeenCalledTimes(1);
		findSession.mockRestore();
	});

	it("is null without a session, and leaves the answer to Better Auth", async () => {
		const refused = await request(server())
			.post("/api/auth/revoke-other-sessions")
			.send({})
			.expect(401);
		expect(refused.body.code).not.toBe("MFA_REQUIRED");
		expect(hooks.seen.at(-1)).toBeNull();
	});

	it("takes the request's headers outside a hook", async () => {
		const { token, user } = await signUp(auth, { password });
		const signedIn = await setup.app
			.get(BetterAuthService)
			.authenticate(new Headers({ Authorization: `Bearer ${token}` }));
		expect(signedIn).toMatchObject({ user: { id: user.id } });
		expect(signedIn?.mfa).toBeUndefined();
		expect(
			await setup.app.get(BetterAuthService).authenticate(new Headers()),
		).toBeNull();
	});
});

describe("mfa e2e: nestjs({ mfa: false })", () => {
	it("adds no session field and never reports a verified second factor", async () => {
		expect(nestjs({ mfa: false }).schema).toBeUndefined();
		const auth = createTestAuth({
			plugins: [
				twoFactor({ skipVerificationOnEnable: true }),
				nestjs({ mfa: false }),
			],
		});

		const { app } = await createTestApp({ auth });
		try {
			const { token } = await signUp(auth, { password });
			const { backupCodes } = await api(auth).enableTwoFactor({
				body: { password },
				headers: new Headers({ Authorization: `Bearer ${token}` }),
			});
			const enrolled = await request(app.getHttpServer())
				.post("/api/auth/two-factor/verify-backup-code")
				.set("Authorization", `Bearer ${token}`)
				.send({ code: backupCodes[0] });
			const sessionToken = enrolled.headers["set-auth-token"] ?? token;

			await request(app.getHttpServer())
				.get("/test/mfa")
				.set("Authorization", `Bearer ${sessionToken}`)
				.expect(401);
		} finally {
			await app.close();
		}
	});
});
