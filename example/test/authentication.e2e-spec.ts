import { eq } from "drizzle-orm";
import { auditEvents, session } from "../src/database/schema/index.ts";
import { createTestApp, type TestApp } from "./support/test-app.ts";
import {
	PASSWORD,
	signUp,
	signUpVerified,
	uniqueEmail,
	verifyEmail,
} from "./support/users.ts";

/** Audit writes run after the response (event listeners): wait for them. */
async function waitFor<T>(read: () => Promise<T | undefined>, ms = 2000) {
	const until = Date.now() + ms;
	for (;;) {
		const value = await read();
		if (value) return value;
		if (Date.now() > until) throw new Error("Timed out");
		await new Promise((resolve) => setTimeout(resolve, 25));
	}
}

describe("authentication", () => {
	let t: TestApp;

	beforeAll(async () => {
		t = await createTestApp();
	});
	afterAll(async () => {
		await t.app.close();
	});

	describe("Better Auth's routes", () => {
		it("are served on /api/auth, outside the /api/v1 global prefix", async () => {
			await t.http().get("/api/auth/ok").expect(200);
			await t.http().get("/api/v1/api/auth/ok").expect(404);
		});

		it("answer CORS preflights for the trusted origins only", async () => {
			const allowed = await t
				.http()
				.options("/api/auth/sign-in/email")
				.set("Origin", "http://localhost:5173")
				.set("Access-Control-Request-Method", "POST");
			expect(allowed.headers["access-control-allow-origin"]).toBe(
				"http://localhost:5173",
			);
			expect(allowed.headers["access-control-allow-credentials"]).toBe("true");

			const refused = await t
				.http()
				.options("/api/auth/sign-in/email")
				.set("Origin", "https://evil.example")
				.set("Access-Control-Request-Method", "POST");
			expect(refused.headers["access-control-allow-origin"]).toBeUndefined();
		});
	});

	describe("public routes (@Public)", () => {
		it("serve health and the sign-in methods read from the Better Auth instance", async () => {
			await t.http().get("/api/v1/health").expect(200, { status: "ok" });
			const { body } = await t.http().get("/api/v1/auth/methods").expect(200);
			expect(body).toMatchObject({
				basePath: "/api/auth",
				emailAndPassword: true,
				magicLink: true,
				twoFactor: true,
				organizations: true,
				apiKeys: true,
				jwks: "/api/auth/jwks",
			});
		});
	});

	describe("sign-up", () => {
		it("normalizes the user (@BeforeCreate), welcomes them (@AfterCreate) and mails the verification link (EmailVerificationHandler)", async () => {
			const email = uniqueEmail("Mixed.Case");
			const user = await signUp(t, {
				email: email.toUpperCase(),
				name: "  Ana  ",
			});

			expect(user.email).toBe(email.toLowerCase());
			expect(user.name).toBe("Ana");
			expect(
				t.mailer.last(user.email, /Verify your Acme email/).text,
			).toContain("http://localhost:5173/verify-email?");
			await waitFor(async () =>
				t.mailer.outbox.find(
					(mail) => mail.to === user.email && /Welcome/.test(mail.subject),
				),
			);
		});

		it("refuses disposable inboxes (@BeforeHook on /sign-up/email)", async () => {
			const response = await t
				.http()
				.post("/api/auth/sign-up/email")
				.send({
					name: "Spam",
					email: "spam@mailinator.com",
					password: PASSWORD,
				})
				.expect(400);
			expect(response.body.code).toBe("DISPOSABLE_EMAIL");
		});
	});

	describe("the session provider", () => {
		it("authenticates the session cookie and the bearer token alike", async () => {
			const email = uniqueEmail();
			const user = await signUp(t, { email });

			const viaBearer = await t
				.http()
				.get("/api/v1/me")
				.set("Authorization", user.bearer)
				.expect(200);
			expect(viaBearer.body.user).toMatchObject({
				id: user.id,
				role: "user",
				locale: "en",
			});
			expect(viaBearer.body.session.mfaVerified).toBe(false);

			const signIn = await t
				.http()
				.post("/api/auth/sign-in/email")
				.send({ email, password: PASSWORD })
				.expect(200);
			const cookies = (signIn.headers["set-cookie"] as unknown as string[]).map(
				(cookie) => cookie.split(";")[0],
			);
			const viaCookie = await t
				.http()
				.get("/api/v1/me")
				.set("Cookie", cookies.join("; "))
				.expect(200);
			expect(viaCookie.body.user.id).toBe(user.id);
		});

		it("answers 401 without credentials, on every route that isn't public", async () => {
			const response = await t.http().get("/api/v1/me").expect(401);
			expect(response.headers["www-authenticate"]).toBeDefined();
		});

		it("reads one field of the user with @CurrentUser('locale'), an additional field", async () => {
			const user = await signUp(t);
			// Better Auth's own route updates the profile, additional fields included.
			await t
				.http()
				.post("/api/auth/update-user")
				.set("Authorization", user.bearer)
				.send({ locale: "pt" })
				.expect(200);
			await t
				.http()
				.get("/api/v1/me/locale")
				.set("Authorization", user.bearer)
				.expect(200, { locale: "pt" });
		});
	});

	describe("sessions in Redis (Better Auth's secondary storage)", () => {
		it("keeps the session in Redis, not in Postgres", async () => {
			const user = await signUp(t);

			expect(await t.redis.exists(`better-auth:${user.token}`)).toBe(1);
			const rows = await t.db
				.select({ id: session.id })
				.from(session)
				.where(eq(session.userId, user.id));
			expect(rows).toEqual([]);
		});

		it("signs a session out on the next request once it ends", async () => {
			const user = await signUp(t);
			await t
				.http()
				.get("/api/v1/me")
				.set("Authorization", user.bearer)
				.expect(200);

			await t
				.http()
				.post("/api/auth/sign-out")
				.set("Authorization", user.bearer)
				.set("Origin", "http://localhost:5173")
				.expect(200);

			expect(await t.redis.exists(`better-auth:${user.token}`)).toBe(0);
			await t
				.http()
				.get("/api/v1/me")
				.set("Authorization", user.bearer)
				.expect(401);
		});
	});

	describe("@Authenticate({ verifiedEmail: true })", () => {
		it("answers 403 email_unverified until the user opens the verification link", async () => {
			const user = await signUp(t);
			const refused = await t
				.http()
				.post("/api/v1/articles")
				.set("Authorization", user.bearer)
				.send({ title: "Hello", body: "World" })
				.expect(403);
			expect(refused.body.error).toBe("email_unverified");

			await verifyEmail(t, user);
			await t
				.http()
				.post("/api/v1/articles")
				.set("Authorization", user.bearer)
				.send({ title: "Hello", body: "World" })
				.expect(201);
		});
	});

	describe("Nest email handlers", () => {
		it("delivers links to the frontend's reset page (PasswordResetHandler), whose token resets the password", async () => {
			const user = await signUpVerified(t);
			await t
				.http()
				.post("/api/auth/request-password-reset")
				.send({ email: user.email, redirectTo: "http://localhost:5173/reset" })
				.expect(200);

			// The link goes to the frontend's reset page, which posts its token.
			const link = new URL(
				t.mailer.link(user.email, /Reset your Acme password/),
			);
			expect(`${link.origin}${link.pathname}`).toBe(
				"http://localhost:5173/reset-password",
			);
			const token = link.searchParams.get("token");

			await t
				.http()
				.post("/api/auth/reset-password")
				.send({ token, newPassword: "a-brand-new-password" })
				.expect(200);
			await t
				.http()
				.post("/api/auth/sign-in/email")
				.send({ email: user.email, password: "a-brand-new-password" })
				.expect(200);
		});

		it("delivers links to the frontend's magic link page (MagicLinkHandler), whose token signs the user in", async () => {
			const user = await signUpVerified(t);
			await t
				.http()
				.post("/api/auth/sign-in/magic-link")
				.send({ email: user.email })
				.expect(200);

			// The link goes to the frontend's page, which hands its token to Better Auth.
			const link = new URL(t.mailer.link(user.email, /Sign in to Acme/));
			expect(`${link.origin}${link.pathname}`).toBe(
				"http://localhost:5173/sign-in/magic-link",
			);
			const response = await t
				.http()
				.get("/api/auth/magic-link/verify")
				.query({ token: link.searchParams.get("token") });
			expect(String(response.headers["set-cookie"])).toContain("session_token");
		});
	});

	describe("audit trail (hooks + request context)", () => {
		it("records sign-ins, from Nest's AuthenticationEvents, with the request id of the Better Auth request (BetterAuthModule middleware)", async () => {
			const user = await signUp(t);
			await t
				.http()
				.post("/api/auth/sign-in/email")
				.set("x-request-id", "req-sign-in-1")
				.send({ email: user.email, password: PASSWORD })
				.expect(200);

			const event = await waitFor(async () => {
				const [row] = await t.db
					.select()
					.from(auditEvents)
					.where(eq(auditEvents.requestId, "req-sign-in-1"));
				return row;
			});
			expect(event).toMatchObject({
				action: "auth.sign-in",
				actorId: user.id,
				metadata: { method: "password" },
			});
		});

		it("records sign-outs, from Nest's AuthenticationEvents", async () => {
			const user = await signUp(t);
			await t
				.http()
				.post("/api/auth/sign-out")
				.set("Authorization", user.bearer)
				.expect(200);

			const event = await waitFor(async () => {
				const rows = await t.db
					.select()
					.from(auditEvents)
					.where(eq(auditEvents.action, "auth.sign-out"));
				return rows.find((row) => row.actorId === user.id);
			});
			expect(event.metadata).toEqual({ sessionId: expect.any(String) });
		});

		it("records refused sign-ins (@AfterHook without a path)", async () => {
			const email = uniqueEmail("wrong-password");
			await signUp(t, { email });
			await t
				.http()
				.post("/api/auth/sign-in/email")
				.send({ email, password: "not-the-password" })
				.expect(401);

			const event = await waitFor(async () => {
				const rows = await t.db
					.select()
					.from(auditEvents)
					.where(eq(auditEvents.action, "auth.sign-in.failed"));
				return rows.find((row) => row.metadata.email === email);
			});
			expect(event.metadata.reason).toBe("INVALID_EMAIL_OR_PASSWORD");
		});
	});

	describe("password hashing (Nest's PasswordHasher)", () => {
		it("stores scrypt hashes from Nest's PasswordHasher", async () => {
			const user = await signUp(t);
			const ctx = await t.auth.$context;
			const accounts = await ctx.internalAdapter.findAccounts(user.id);
			expect(accounts[0].password).toMatch(/^\$scrypt\$/);
		});
	});
});
