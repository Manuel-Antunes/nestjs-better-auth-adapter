import type { INestApplication } from "@nestjs/common";
import request from "supertest";
import {
	createTestApp,
	createTestAuth,
	signUp,
	TestResolver,
	type TestAuth,
} from "../shared/app.ts";

describe("graphql auth e2e", () => {
	let app: INestApplication;
	let auth: TestAuth;

	const query = (source: string, token?: string) => {
		const req = request(app.getHttpServer())
			.post("/graphql")
			.set("Content-Type", "application/json");
		if (token) req.set("Authorization", `Bearer ${token}`);
		return req.send({ query: source }).expect(200);
	};

	beforeAll(async () => {
		auth = createTestAuth();
		({ app } = await createTestApp({
			auth,
			graphql: true,
			providers: [TestResolver],
		}));
	});

	afterAll(async () => {
		await app.close();
	});

	it("should resolve a public query without auth", async () => {
		const response = await query("{ publicHello }");

		expect(response.body?.data?.publicHello).toBe("ok");
	});

	it("should resolve an optional query without auth", async () => {
		const response = await query("{ optionalAuthenticated }");

		expect(response.body?.data?.optionalAuthenticated).toBe(false);
	});

	it("should resolve an optional query with auth", async () => {
		const { token } = await signUp(auth);
		const response = await query(
			"{ optionalAuthenticated }",
			token ?? undefined,
		);

		expect(response.body?.data?.optionalAuthenticated).toBe(true);
	});

	it("should require auth for a protected query", async () => {
		const response = await query("{ protectedUserId }");

		expect(Array.isArray(response.body?.errors)).toBe(true);
		expect(response.body?.data).toBeNull();
	});

	it("should resolve a protected query with auth", async () => {
		const { token, user } = await signUp(auth);
		const response = await query("{ protectedUserId }", token ?? undefined);

		expect(response.body?.data?.protectedUserId).toBe(user.id);
	});
});
