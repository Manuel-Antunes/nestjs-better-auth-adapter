import cors from "@fastify/cors";
import { Module } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import { AuthenticationModule } from "@nestjs/authentication";
import { FastifyAdapter } from "@nestjs/platform-fastify";
import request from "supertest";
import {
	BetterAuthModule,
	type BetterAuthModuleOptions,
} from "../../src/index.ts";
import {
	createTestApp,
	createTestAuth,
	TestController,
} from "../shared/app.ts";
import { initTestApplication } from "../shared/http-adapter.ts";

const TRUSTED_ORIGIN = "http://localhost:3000";
const isFastify = process.env.TEST_HTTP_ADAPTER === "fastify";
const fastifyOnly = isFastify ? it : it.skip;

/** A Fastify app with `@fastify/cors` registered at the app level before Nest boots. */
async function createFastifyAppWithCors(
	module: Omit<BetterAuthModuleOptions, "auth"> = {},
) {
	const auth = createTestAuth({ trustedOrigins: [TRUSTED_ORIGIN] });

	@Module({
		imports: [
			AuthenticationModule.forRoot(),
			BetterAuthModule.forRoot({ auth, ...module }),
		],
		controllers: [TestController],
	})
	class AppModule {}

	const moduleRef = await Test.createTestingModule({
		imports: [AppModule],
	}).compile();
	const adapter = new FastifyAdapter();
	await adapter.register(cors as never, {
		origin: [TRUSTED_ORIGIN],
		credentials: true,
	});
	const app = moduleRef.createNestApplication(adapter, {
		bodyParser: false,
		logger: false,
	});
	return initTestApplication(app);
}

describe("cors e2e", () => {
	it("should apply trustedOrigins CORS headers on Better Auth routes", async () => {
		const { app } = await createTestApp({
			auth: createTestAuth({ trustedOrigins: [TRUSTED_ORIGIN] }),
		});

		try {
			const server = app.getHttpServer();
			const optionsResponse = await request(server)
				.options("/api/auth/sign-in/email")
				.set("Origin", TRUSTED_ORIGIN)
				.set("Access-Control-Request-Method", "POST")
				.set(
					"Access-Control-Request-Headers",
					"content-type, stripe-signature",
				);

			expect(optionsResponse.status).toBe(204);
			expect(optionsResponse.headers["access-control-allow-origin"]).toBe(
				TRUSTED_ORIGIN,
			);
			expect(optionsResponse.headers["access-control-allow-credentials"]).toBe(
				"true",
			);
			expect(optionsResponse.headers["access-control-allow-headers"]).toBe(
				"content-type, stripe-signature",
			);

			const okResponse = await request(server)
				.get("/api/auth/ok")
				.set("Origin", TRUSTED_ORIGIN);

			expect(okResponse.status).toBe(200);
			expect(okResponse.headers["access-control-allow-origin"]).toBe(
				TRUSTED_ORIGIN,
			);
			expect(okResponse.headers["access-control-allow-credentials"]).toBe(
				"true",
			);
		} finally {
			await app.close();
		}
	});

	it("should match origins as Better Auth does: wildcards, and IP ranges that admit IPs only", async () => {
		const { app } = await createTestApp({
			auth: createTestAuth({
				trustedOrigins: ["https://*.example.com", "http://192.168.*.*"],
			}),
		});

		try {
			const origin = async (value: string) =>
				(
					await request(app.getHttpServer())
						.get("/api/auth/ok")
						.set("Origin", value)
						.expect(200)
				).headers["access-control-allow-origin"];

			expect(await origin("https://app.example.com")).toBe(
				"https://app.example.com",
			);
			expect(await origin("http://192.168.0.10")).toBe("http://192.168.0.10");
			expect(await origin("http://192.168.attacker.com")).toBeUndefined();
			expect(await origin("https://example.com.attacker.com")).toBeUndefined();
		} finally {
			await app.close();
		}
	});

	it("should leave CORS for the app's own routes to the app", async () => {
		const { app } = await createTestApp({
			auth: createTestAuth({ trustedOrigins: [TRUSTED_ORIGIN] }),
		});

		try {
			const response = await request(app.getHttpServer())
				.get("/test/public")
				.set("Origin", TRUSTED_ORIGIN)
				.expect(200);
			expect(response.headers["access-control-allow-origin"]).toBeUndefined();
		} finally {
			await app.close();
		}
	});

	it("should not add CORS headers with trustedOriginsCors: false", async () => {
		const { app } = await createTestApp({
			auth: createTestAuth({ trustedOrigins: [TRUSTED_ORIGIN] }),
			module: { trustedOriginsCors: false },
		});

		try {
			const okResponse = await request(app.getHttpServer())
				.get("/api/auth/ok")
				.set("Origin", TRUSTED_ORIGIN);

			expect(okResponse.status).toBe(200);
			expect(okResponse.headers["access-control-allow-origin"]).toBeUndefined();
		} finally {
			await app.close();
		}
	});

	it("should refuse function-based trustedOrigins unless its CORS is off", async () => {
		await expect(
			createTestApp({
				auth: createTestAuth({ trustedOrigins: async () => [TRUSTED_ORIGIN] }),
			}),
		).rejects.toThrow("trustedOrigins must be a string array");
	});

	fastifyOnly(
		"should coexist with app-level Fastify CORS when @fastify/cors is already registered",
		async () => {
			const app = await createFastifyAppWithCors();
			try {
				const server = app.getHttpServer();
				const optionsResponse = await request(server)
					.options("/api/auth/sign-in/email")
					.set("Origin", TRUSTED_ORIGIN)
					.set("Access-Control-Request-Method", "POST")
					.set("Access-Control-Request-Headers", "content-type");

				expect(optionsResponse.status).toBe(204);
				expect(optionsResponse.headers["access-control-allow-origin"]).toBe(
					TRUSTED_ORIGIN,
				);

				const okResponse = await request(server)
					.get("/api/auth/ok")
					.set("Origin", TRUSTED_ORIGIN);

				expect(okResponse.status).toBe(200);
				expect(okResponse.headers["access-control-allow-origin"]).toBe(
					TRUSTED_ORIGIN,
				);
				expect(okResponse.headers["access-control-allow-credentials"]).toBe(
					"true",
				);
			} finally {
				await app.close();
			}
		},
	);

	fastifyOnly(
		"should not add Better Auth route CORS on Fastify with trustedOriginsCors: false",
		async () => {
			const app = await createFastifyAppWithCors({ trustedOriginsCors: false });
			try {
				const server = app.getHttpServer();
				const optionsResponse = await request(server)
					.options("/api/auth/sign-in/email")
					.set("Origin", TRUSTED_ORIGIN)
					.set("Access-Control-Request-Method", "POST")
					.set("Access-Control-Request-Headers", "content-type");

				expect(optionsResponse.status).toBe(204);
				expect(optionsResponse.headers["access-control-allow-origin"]).toBe(
					TRUSTED_ORIGIN,
				);

				const okResponse = await request(server)
					.get("/api/auth/ok")
					.set("Origin", TRUSTED_ORIGIN);

				expect(okResponse.status).toBe(200);
				expect(
					okResponse.headers["access-control-allow-origin"],
				).toBeUndefined();
				expect(
					okResponse.headers["access-control-allow-credentials"],
				).toBeUndefined();
			} finally {
				await app.close();
			}
		},
	);
});
