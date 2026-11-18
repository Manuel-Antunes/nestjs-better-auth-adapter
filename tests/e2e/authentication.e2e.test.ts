import request from "supertest";
import {
	createTestApp,
	createTestAuth,
	signUp,
	verifyEmail,
} from "../shared/app.ts";

describe("authentication e2e", () => {
	let setup: Awaited<ReturnType<typeof createTestApp>>;

	beforeAll(async () => {
		setup = await createTestApp({ auth: createTestAuth() });
	});

	afterAll(async () => {
		await setup.app.close();
	});

	const server = () => setup.app.getHttpServer();

	it("rejects a protected route without credentials", async () => {
		await request(server()).get("/test/protected").expect(401);
	});

	it("rejects an invalid bearer token", async () => {
		await request(server())
			.get("/test/protected")
			.set("Authorization", "Bearer invalid-token")
			.expect(401);
	});

	it("resolves Better Auth's user and session through @CurrentUser() and @CurrentSession()", async () => {
		const { token, user } = await signUp(setup.auth);

		const response = await request(server())
			.get("/test/protected")
			.set("Authorization", `Bearer ${token}`)
			.expect(200);

		expect(response.body.user).toMatchObject({
			id: user.id,
			email: user.email,
		});
		expect(response.body.session).toMatchObject({ userId: user.id });
	});

	it("resolves the user from the session cookie", async () => {
		const email = `cookie-${Date.now()}@example.com`;
		const signUpResponse = await request(server())
			.post("/api/auth/sign-up/email")
			.send({ name: "Cookie", email, password: "password-123456" })
			.expect(200);

		const response = await request(server())
			.get("/test/protected")
			.set("Cookie", signUpResponse.headers["set-cookie"])
			.expect(200);

		expect(response.body.user.email).toBe(email);
	});

	it("keeps Better Auth's own routes outside the guard", async () => {
		await request(server()).get("/api/auth/ok").expect(200);
	});

	it("exposes the user through AuthenticationContext", async () => {
		const { token, user } = await signUp(setup.auth);

		const response = await request(server())
			.get("/test/context")
			.set("Authorization", `Bearer ${token}`)
			.expect(200);

		expect(response.body.id).toBe(user.id);
	});

	describe("@Public()", () => {
		it("allows anonymous access", async () => {
			await request(server()).get("/test/public").expect(200);
		});

		it("runs no provider, so @CurrentUser() is null", async () => {
			const { token } = await signUp(setup.auth);

			const response = await request(server())
				.get("/test/public")
				.set("Authorization", `Bearer ${token}`)
				.expect(200);

			expect(response.body.user).toBeNull();
		});
	});

	describe("@Authenticate({ optional: true })", () => {
		it("lets anonymous callers through", async () => {
			const response = await request(server())
				.get("/test/optional")
				.expect(200);

			expect(response.body).toEqual({ authenticated: false, userId: null });
		});

		it("resolves the user when credentials are present", async () => {
			const { token, user } = await signUp(setup.auth);

			const response = await request(server())
				.get("/test/optional")
				.set("Authorization", `Bearer ${token}`)
				.expect(200);

			expect(response.body).toEqual({ authenticated: true, userId: user.id });
		});
	});

	describe("@Authenticate({ verifiedEmail: true })", () => {
		it("answers 403 email_unverified while the email is unverified", async () => {
			const { token } = await signUp(setup.auth);

			const response = await request(server())
				.get("/test/verified")
				.set("Authorization", `Bearer ${token}`)
				.expect(403);

			expect(response.body.error).toBe("email_unverified");
		});

		it("allows a verified email", async () => {
			const { token, user } = await signUp(setup.auth);
			await verifyEmail(setup.auth, user.id);

			const response = await request(server())
				.get("/test/verified")
				.set("Authorization", `Bearer ${token}`)
				.expect(200);

			expect(response.body.email).toBe(user.email);
		});
	});

	describe("@Authenticate({ providers })", () => {
		it("accepts the session on a BetterAuthSessionProvider route", async () => {
			const { token } = await signUp(setup.auth);

			await request(server())
				.get("/test/session-only")
				.set("Authorization", `Bearer ${token}`)
				.expect(200);
		});

		it("refuses a session on an ApiKeyProvider route", async () => {
			const { token } = await signUp(setup.auth);

			await request(server())
				.get("/test/api-key-only")
				.set("Authorization", `Bearer ${token}`)
				.expect(401);
		});
	});

	it("does not satisfy @Authenticate({ mfa: true }) without a second factor", async () => {
		const { token } = await signUp(setup.auth);

		const response = await request(server())
			.get("/test/mfa")
			.set("Authorization", `Bearer ${token}`)
			.expect(401);

		expect(response.body.error).toBe("mfa_required");
	});
});

describe("authentication e2e: providers option", () => {
	it("leaves the session provider out with providers.session: false", async () => {
		const auth = createTestAuth();
		const { app } = await createTestApp({
			auth,
			module: { providers: { session: false } },
		});

		try {
			const { token } = await signUp(auth);
			await request(app.getHttpServer())
				.get("/test/protected")
				.set("Authorization", `Bearer ${token}`)
				.expect(401);
		} finally {
			await app.close();
		}
	});
});
