import {
	type AuthenticationEvent,
	AuthenticationEvents,
} from "@nestjs/authentication";
import { base32 } from "@better-auth/utils/base32";
import { createOTP } from "@better-auth/utils/otp";
import { magicLink } from "better-auth/plugins/magic-link";
import { twoFactor } from "better-auth/plugins/two-factor";
import request from "supertest";
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

/** A cheap password hash, as `createTestAuth()`'s, for a config that sets its own `emailAndPassword`. */
const fastPassword = {
	hash: async (plain: string) => `plain:${plain}`,
	verify: async ({ hash, password }: { hash: string; password: string }) =>
		hash === `plain:${password}`,
};

/** The cookies a browser holds after `response`, as a `Cookie` header value. */
function cookiesOf(response: request.Response): string {
	const setCookies =
		(response.headers["set-cookie"] as unknown as string[] | undefined) ?? [];
	return setCookies
		.filter((cookie) => !/max-age=0/i.test(cookie))
		.map((cookie) => cookie.split(";")[0])
		.join("; ");
}

const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

/** Records what `AuthenticationEvents` publishes. */
function recordEvents(setup: Awaited<ReturnType<typeof createTestApp>>) {
	const events: AuthenticationEvent[] = [];
	setup.app
		.get(AuthenticationEvents)
		.events$.subscribe((event) => events.push(event));
	return events;
}

describe("authentication events", () => {
	const magicLinks = new Map<string, string>();
	const resetTokens = new Map<string, string>();
	const verificationLinks = new Map<string, string>();
	let auth: TestAuth;
	let setup: Awaited<ReturnType<typeof createTestApp>>;
	let events: AuthenticationEvent[];

	beforeAll(async () => {
		auth = createTestAuth({
			baseURL: "http://localhost",
			emailAndPassword: {
				enabled: true,
				password: fastPassword,
				sendResetPassword: async ({ user, token }) => {
					resetTokens.set(user.email, token);
				},
			},
			emailVerification: {
				sendVerificationEmail: async ({ user, url }) => {
					verificationLinks.set(user.email, url);
				},
			},
			plugins: [
				twoFactor(),
				magicLink({
					sendMagicLink: async ({ email, url }) => {
						magicLinks.set(email, url);
					},
				}),
			],
		});
		setup = await createTestApp({ auth });
		events = recordEvents(setup);
	});

	beforeEach(() => {
		events.length = 0;
	});

	afterAll(async () => {
		await setup.app.close();
	});

	const server = () => setup.app.getHttpServer();
	const path = (url: string) => {
		const { pathname, search } = new URL(url);
		return pathname + search;
	};

	async function signIn(email: string) {
		const response = await request(server())
			.post("/api/auth/sign-in/email")
			.send({ email, password })
			.expect(200);
		const session = await auth.api.getSession({
			headers: new Headers(bearer(response.body.token)),
		});
		return { response, token: response.body.token as string, session };
	}

	describe("sign-in", () => {
		it("publishes a sign-up's sign-in", async () => {
			const { user, token } = await signUp(auth, { password });
			const session = await auth.api.getSession({
				headers: new Headers(bearer(token as string)),
			});

			expect(events).toEqual([
				{
					type: "sign-in",
					userId: user.id,
					sessionId: session?.session.id,
					method: "password",
				},
			]);
		});

		it("publishes a password sign-in with its session", async () => {
			const email = uniqueEmail();
			const { user } = await signUp(auth, { email, password });
			events.length = 0;

			const { session } = await signIn(email);

			expect(events).toEqual([
				{
					type: "sign-in",
					userId: user.id,
					sessionId: session?.session.id,
					method: "password",
				},
			]);
		});

		it("publishes nothing for a refused sign-in", async () => {
			const email = uniqueEmail();
			await signUp(auth, { email, password });
			events.length = 0;

			await request(server())
				.post("/api/auth/sign-in/email")
				.send({ email, password: "wrong-password-1" })
				.expect(401);

			expect(events).toEqual([]);
		});
	});

	describe("sign-out", () => {
		it("publishes a sign-out, with a Bearer token or a cookie", async () => {
			const email = uniqueEmail();
			const { user } = await signUp(auth, { email, password });

			const withToken = await signIn(email);
			events.length = 0;
			await request(server())
				.post("/api/auth/sign-out")
				.set(bearer(withToken.token))
				.expect(200);
			expect(events).toEqual([
				{
					type: "sign-out",
					userId: user.id,
					sessionId: withToken.session?.session.id,
				},
			]);

			const withCookie = await signIn(email);
			events.length = 0;
			await request(server())
				.post("/api/auth/sign-out")
				.set("Cookie", cookiesOf(withCookie.response))
				.expect(200);
			expect(events).toEqual([
				{
					type: "sign-out",
					userId: user.id,
					sessionId: withCookie.session?.session.id,
				},
			]);
		});

		it("publishes nothing for a sign-out without a session", async () => {
			await request(server()).post("/api/auth/sign-out").expect(200);
			expect(events).toEqual([]);
		});

		it("publishes the sessions revoke-session, revoke-other-sessions and revoke-sessions end", async () => {
			const email = uniqueEmail();
			const { user } = await signUp(auth, { email, password });
			const [current, second, third] = [
				await signIn(email),
				await signIn(email),
				await signIn(email),
			];
			const stranger = await signUp(auth, { password });
			events.length = 0;

			await request(server())
				.post("/api/auth/revoke-session")
				.set(bearer(current.token))
				.send({ token: second.token })
				.expect(200);
			// Someone else's session: Better Auth answers 200 and ends nothing.
			await request(server())
				.post("/api/auth/revoke-session")
				.set(bearer(current.token))
				.send({ token: stranger.token })
				.expect(200);
			expect(events).toEqual([
				{
					type: "sign-out",
					userId: user.id,
					sessionId: second.session?.session.id,
				},
			]);

			events.length = 0;
			await request(server())
				.post("/api/auth/revoke-other-sessions")
				.set(bearer(current.token))
				.expect(200);
			// The sign-up's session, and the third one.
			expect(events).toHaveLength(2);
			expect(events).toContainEqual({
				type: "sign-out",
				userId: user.id,
				sessionId: third.session?.session.id,
			});
			expect(events).not.toContainEqual(
				expect.objectContaining({ sessionId: current.session?.session.id }),
			);

			events.length = 0;
			await request(server())
				.post("/api/auth/revoke-sessions")
				.set(bearer(current.token))
				.expect(200);
			expect(events).toEqual([
				{ type: "sign-out", userId: user.id, everywhere: true },
			]);
		});
	});

	describe("second factor", () => {
		/** The current code of the authenticator `enable` returned. */
		const totpOf = (totpURI: string) =>
			createOTP(
				base32.decode(new URL(totpURI).searchParams.get("secret") ?? ""),
			).totp();

		/** The session token after a response that may have rotated it. */
		const tokenAfter = (response: request.Response, previous: string) =>
			(response.headers["set-auth-token"] as string | undefined) ?? previous;

		it("publishes an enrollment, a challenged sign-in, its failures and verifications, new codes and disabling", async () => {
			const email = uniqueEmail();
			const { user, token: signUpToken } = await signUp(auth, {
				email,
				password,
			});
			let token = signUpToken as string;
			events.length = 0;

			const enabled = await request(server())
				.post("/api/auth/two-factor/enable")
				.set(bearer(token))
				.send({ password })
				.expect(200);
			// Not enabled until a code confirms the authenticator.
			expect(events).toEqual([]);

			const confirmed = await request(server())
				.post("/api/auth/two-factor/verify-totp")
				.set(bearer(token))
				.send({ code: await totpOf(enabled.body.totpURI) })
				.expect(200);
			token = tokenAfter(confirmed, token);
			// The rotated session is no sign-in.
			expect(events).toEqual([
				{ type: "mfa-enabled", userId: user.id, replaced: false },
			]);

			events.length = 0;
			const challenged = await request(server())
				.post("/api/auth/sign-in/email")
				.send({ email, password })
				.expect(200);
			expect(challenged.body.twoFactorRedirect).toBe(true);
			expect(events).toEqual([
				{
					type: "sign-in",
					userId: user.id,
					method: "password",
					mfa: "pending",
				},
			]);

			events.length = 0;
			const cookies = cookiesOf(challenged);
			await request(server())
				.post("/api/auth/two-factor/verify-totp")
				.set("Cookie", cookies)
				.send({ code: "000000" })
				.expect(401);
			expect(events).toEqual([
				{
					type: "mfa-failed",
					userId: user.id,
					method: "totp",
					failures: 1,
					locked: false,
				},
			]);

			events.length = 0;
			await request(server())
				.post("/api/auth/two-factor/verify-totp")
				.set("Cookie", cookies)
				.send({ code: await totpOf(enabled.body.totpURI) })
				.expect(200);
			expect(events).toEqual([
				{ type: "mfa-verified", userId: user.id, method: "totp" },
			]);

			events.length = 0;
			const generated = await request(server())
				.post("/api/auth/two-factor/generate-backup-codes")
				.set(bearer(token))
				.send({ password })
				.expect(200);
			expect(events).toEqual([
				{
					type: "recovery-codes-generated",
					userId: user.id,
					count: generated.body.backupCodes.length,
				},
			]);

			const again = await request(server())
				.post("/api/auth/sign-in/email")
				.send({ email, password })
				.expect(200);
			events.length = 0;
			await request(server())
				.post("/api/auth/two-factor/verify-backup-code")
				.set("Cookie", cookiesOf(again))
				.send({ code: generated.body.backupCodes[0] })
				.expect(200);
			expect(events).toEqual([
				{ type: "mfa-verified", userId: user.id, method: "recovery-code" },
			]);

			events.length = 0;
			await request(server())
				.post("/api/auth/two-factor/disable")
				.set(bearer(token))
				.send({ password })
				.expect(200);
			expect(events).toEqual([{ type: "mfa-disabled", userId: user.id }]);
		});
	});

	describe("password reset", () => {
		it("publishes a request, with the user when the address has one", async () => {
			const email = uniqueEmail();
			const { user } = await signUp(auth, { email, password });
			events.length = 0;

			await request(server())
				.post("/api/auth/request-password-reset")
				.send({ email: email.toUpperCase() })
				.expect(200);
			await request(server())
				.post("/api/auth/request-password-reset")
				.send({ email: "nobody@example.com" })
				.expect(200);

			expect(events).toEqual([
				{ type: "password-reset-requested", email, userId: user.id },
				{ type: "password-reset-requested", email: "nobody@example.com" },
			]);
		});

		it("publishes a reset, and nothing for a bad token", async () => {
			const email = uniqueEmail();
			const { user } = await signUp(auth, { email, password });
			await api(auth).requestPasswordReset({ body: { email } });
			events.length = 0;

			await request(server())
				.post("/api/auth/reset-password")
				.send({ token: "not-a-token", newPassword: "new-password-123" })
				.expect(400);
			await request(server())
				.post("/api/auth/reset-password")
				.send({
					token: resetTokens.get(email),
					newPassword: "new-password-123",
				})
				.expect(200);

			expect(events).toEqual([{ type: "password-reset", userId: user.id }]);
		});
	});

	describe("email verification", () => {
		it("publishes a verified address, once", async () => {
			const email = uniqueEmail();
			const { user } = await signUp(auth, { email, password });
			await api(auth).sendVerificationEmail({ body: { email } });
			const link = verificationLinks.get(email) ?? "";
			events.length = 0;

			await request(server()).get(path(link));
			// Already verified: Better Auth changes nothing.
			await request(server()).get(path(link));

			expect(events).toEqual([
				{ type: "email-verified", userId: user.id, email },
			]);
		});
	});

	describe("magic link", () => {
		it("publishes the sign-in, and the address the link proved", async () => {
			const email = uniqueEmail();
			const { user } = await signUp(auth, { email, password });
			await api(auth).signInMagicLink({
				body: { email },
				headers: new Headers(),
			});
			events.length = 0;

			const response = await request(server())
				.get(path(magicLinks.get(email) ?? ""))
				.expect(302);
			const session = await auth.api.getSession({
				headers: new Headers({ cookie: cookiesOf(response) }),
			});

			expect(events).toEqual([
				{ type: "email-verified", userId: user.id, email },
				{
					type: "sign-in",
					userId: user.id,
					sessionId: session?.session.id,
					method: "magic-link",
				},
			]);
		});

		it("publishes a refused link", async () => {
			await request(server())
				.get("/api/auth/magic-link/verify?token=not-a-link")
				.expect(302);
			expect(events).toEqual([
				{ type: "magic-link-refused", reason: "unknown" },
			]);
		});
	});
});

describe("authentication events: nestjs() after twoFactor()", () => {
	let auth: TestAuth;
	let setup: Awaited<ReturnType<typeof createTestApp>>;
	let events: AuthenticationEvent[];

	beforeAll(async () => {
		auth = createTestAuth({
			baseURL: "http://localhost",
			plugins: [twoFactor({ skipVerificationOnEnable: true }), nestjs()],
		});
		setup = await createTestApp({ auth });
		events = recordEvents(setup);
	});

	afterAll(async () => {
		await setup.app.close();
	});

	it("publishes enabling without a code, and a challenged sign-in as pending", async () => {
		const email = uniqueEmail();
		const { user, token } = await signUp(auth, { email, password });
		events.length = 0;

		await api(auth).enableTwoFactor({
			body: { password },
			headers: new Headers(bearer(token as string)),
		});
		expect(events).toEqual([
			{ type: "mfa-enabled", userId: user.id, replaced: false },
		]);

		events.length = 0;
		const response = await request(setup.app.getHttpServer())
			.post("/api/auth/sign-in/email")
			.send({ email, password })
			.expect(200);
		expect(response.body.twoFactorRedirect).toBe(true);
		expect(events).toEqual([
			{ type: "sign-in", userId: user.id, method: "password", mfa: "pending" },
		]);
	});
});

describe("authentication events: nestjs({ events: false })", () => {
	it("publishes nothing", async () => {
		const auth = createTestAuth({ plugins: [nestjs({ events: false })] });
		const setup = await createTestApp({ auth });
		const events = recordEvents(setup);

		const email = uniqueEmail();
		await signUp(auth, { email, password });
		await request(setup.app.getHttpServer())
			.post("/api/auth/sign-in/email")
			.send({ email, password })
			.expect(200);

		expect(events).toEqual([]);
		await setup.app.close();
	});
});
