import type { INestApplication } from "@nestjs/common";
import request from "supertest";
import { BetterAuthService } from "../../src/index.ts";
import {
	type BetterAuthOptions,
	createTestApp,
	createTestAuth,
	uniqueEmail,
} from "../shared/app.ts";
import { withEnv } from "../shared/env.ts";

type Server = Parameters<typeof request>[0];

/** Signs up over HTTP under `basePath`: Better Auth's own route, raw body and all. */
async function signUp(server: Server, basePath: string) {
	const response = await request(server)
		.post(`${basePath}/sign-up/email`)
		.send({
			name: "Base Path",
			email: uniqueEmail(),
			password: "password-123456",
		})
		.expect(200);
	return response.body as { token: string };
}

/**
 * Better Auth's routes are served where Better Auth's own router expects
 * them: the path of its `baseURL` when it has one, else its `basePath`.
 */
describe("base path e2e", () => {
	let app: INestApplication | undefined;

	afterEach(async () => {
		await app?.close();
		app = undefined;
	});

	const serve = async (
		options: Partial<BetterAuthOptions>,
		globalPrefix?: string,
	) => {
		({ app } = await createTestApp({
			auth: createTestAuth(options),
			globalPrefix,
		}));
		return app.getHttpServer();
	};

	it("serves the routes under a custom basePath, and only there", async () => {
		const server = await serve({ basePath: "/identity" });

		await request(server).get("/identity/ok").expect(200, { ok: true });
		await request(server).get("/api/auth/ok").expect(404);
	});

	it("serves a basePath written without its leading slash", async () => {
		const server = await serve({ basePath: "identity" });

		await request(server).get("/identity/ok").expect(200, { ok: true });
	});

	it("serves a basePath written with a trailing slash", async () => {
		const server = await serve({ basePath: "/identity/" });

		await request(server).get("/identity/ok").expect(200, { ok: true });
	});

	it("serves the path of BETTER_AUTH_URL, as Better Auth does", async () => {
		await withEnv(
			{ BETTER_AUTH_URL: "http://localhost:3000/identity" },
			async () => {
				const server = await serve({ basePath: undefined });

				await request(server).get("/identity/ok").expect(200, { ok: true });
			},
		);
	});

	it("serves the path of a baseURL, which Better Auth prefers to basePath", async () => {
		const server = await serve({
			baseURL: "http://localhost:3000/identity",
			basePath: "/ignored",
		});

		await request(server).get("/identity/ok").expect(200, { ok: true });
		await request(server).get("/ignored/ok").expect(404);
		expect(app?.get(BetterAuthService).basePath).toBe("/identity");
	});

	it("serves basePath under a baseURL without a path", async () => {
		const server = await serve({
			baseURL: "http://localhost:3000",
			basePath: "/identity",
		});

		await request(server).get("/identity/ok").expect(200, { ok: true });
	});

	it("keeps a basePath inside the global prefix where it is, not under it twice", async () => {
		const server = await serve({ basePath: "/api/v1/auth" }, "api/v1");

		const { token } = await signUp(server, "/api/v1/auth");
		await request(server).get("/api/v1/api/v1/auth/ok").expect(404);
		await request(server)
			.get("/api/v1/test/protected")
			.set("Authorization", `Bearer ${token}`)
			.expect(200);
	});

	it("parses the bodies of the app's routes, not of Better Auth's, under a custom basePath", async () => {
		const server = await serve({ basePath: "/identity" });

		// Better Auth reads its own raw body: a parsed one would hang or fail.
		await signUp(server, "/identity");
	});

	it("refuses to serve Better Auth at the root of the app", async () => {
		await expect(serve({ basePath: "/" })).rejects.toThrow(
			/Better Auth's routes need a path of their own/,
		);
	});
});
