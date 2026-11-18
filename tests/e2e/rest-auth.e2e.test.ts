import type { INestApplication } from "@nestjs/common";
import request from "supertest";
import {
	createTestApp,
	createTestAuth,
	signUp,
	uniqueEmail,
	type TestAuth,
} from "../shared/app.ts";

describe("rest auth e2e", () => {
	let app: INestApplication;
	let auth: TestAuth;

	beforeAll(async () => {
		auth = createTestAuth();
		({ app } = await createTestApp({ auth }));
	});

	afterAll(async () => {
		await app.close();
	});

	it("should not be able to access protected route without auth", async () => {
		await request(app.getHttpServer())
			.get("/test/protected")
			.expect(401)
			.expect((res) => {
				expect(res.body?.message).toBeDefined();
			});
	});

	it("should be able to access public route without auth", async () => {
		const response = await request(app.getHttpServer())
			.get("/test/public")
			.expect(200);

		expect(response.body).toMatchObject({ ok: true });
	});

	it("should be able to access an optional protected route without auth", async () => {
		const response = await request(app.getHttpServer())
			.get("/test/optional")
			.expect(200);

		expect(response.body).toMatchObject({ authenticated: false });
	});

	it("should be able to access an optional protected route with auth", async () => {
		const { token, user } = await signUp(auth);

		const response = await request(app.getHttpServer())
			.get("/test/optional")
			.set("Authorization", `Bearer ${token}`)
			.expect(200);

		expect(response.body).toMatchObject({
			authenticated: true,
			userId: user.id,
		});
	});

	it("should be able to sign up and authenticate", async () => {
		const { token, user } = await signUp(auth);

		const response = await request(app.getHttpServer())
			.get("/test/protected")
			.set("Authorization", `Bearer ${token}`)
			.expect(200);

		expect(response.body).toMatchObject({
			user: expect.objectContaining({
				id: user.id,
				name: user.name,
				email: user.email,
			}),
			session: expect.objectContaining({ userId: user.id }),
		});
	});

	it("should authenticate with a session cookie", async () => {
		const agent = request.agent(app.getHttpServer());
		await agent
			.post("/api/auth/sign-up/email")
			.send({
				name: "Cookie User",
				email: uniqueEmail(),
				password: "password-123456",
			})
			.expect(200);

		const response = await agent.get("/test/protected").expect(200);
		expect(response.body.user.name).toBe("Cookie User");
	});

	it("should authenticate with a global prefix", async () => {
		const prefixedAuth = createTestAuth();
		const prefixed = await createTestApp({
			auth: prefixedAuth,
			globalPrefix: "v1",
		});

		try {
			const signUpResponse = await request(prefixed.app.getHttpServer())
				// Better Auth's routes stay at /api/auth, not /v1/api/auth: the
				// path is changed through the auth instance's basePath.
				.post("/api/auth/sign-up/email")
				.set("Content-Type", "application/json")
				.send({
					name: "Prefixed User",
					email: uniqueEmail(),
					password: "password-123456",
				})
				.expect(200);

			const { token, user } = signUpResponse.body ?? {};
			expect(token).toBeDefined();
			expect(user?.id).toBeDefined();

			const response = await request(prefixed.app.getHttpServer())
				.get("/v1/test/protected")
				.set("Authorization", `Bearer ${token}`)
				.expect(200);

			expect(response.body).toMatchObject({
				user: expect.objectContaining({ id: user.id }),
			});
		} finally {
			await prefixed.app.close();
		}
	});
});
