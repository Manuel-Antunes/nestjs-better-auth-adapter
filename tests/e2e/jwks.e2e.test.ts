import type { INestApplication } from "@nestjs/common";
import { createAuthMiddleware } from "better-auth/api";
import { jwt } from "better-auth/plugins/jwt";
import request from "supertest";
import type { BetterAuthModuleOptions } from "../../src/index.ts";
import {
	type BetterAuthOptions,
	createTestApp,
	createTestAuth,
} from "../shared/app.ts";

const ORIGIN = "http://localhost:3000";
/** `@better-auth/oauth-provider`'s policy for its discovery documents. */
const DEFAULT =
	"public, max-age=15, stale-while-revalidate=15, stale-if-error=86400";

describe("the jwt() plugin's JWKS", () => {
	let app: INestApplication | undefined;

	afterEach(async () => {
		await app?.close();
		app = undefined;
	});

	const setup = async (
		module: Omit<BetterAuthModuleOptions, "auth"> = {},
		auth: Partial<BetterAuthOptions> = {},
	) => {
		({ app } = await createTestApp({
			auth: createTestAuth({ baseURL: ORIGIN, plugins: [jwt()], ...auth }),
			module,
			controllers: [],
		}));
		return app.getHttpServer();
	};

	it("is cacheable by default, as the discovery documents pointing at it", async () => {
		const response = await request(await setup())
			.get("/api/auth/jwks")
			.expect(200);
		expect(response.body.keys).toEqual(expect.any(Array));
		expect(response.headers["cache-control"]).toBe(DEFAULT);
	});

	it("takes the app's policy", async () => {
		const policy =
			"public, max-age=300, stale-while-revalidate=86400, stale-if-error=86400";
		const response = await request(await setup({ jwksCacheControl: policy }))
			.get("/api/auth/jwks?refresh=1")
			.expect(200);
		expect(response.headers["cache-control"]).toBe(policy);
	});

	it("is sent without one with jwksCacheControl: false", async () => {
		const response = await request(await setup({ jwksCacheControl: false }))
			.get("/api/auth/jwks")
			.expect(200);
		expect(response.headers["cache-control"]).toBeUndefined();
	});

	it("is found at the plugin's jwksPath", async () => {
		const server = await setup(
			{},
			{ plugins: [jwt({ jwks: { jwksPath: "/.well-known/jwks.json" } })] },
		);
		const response = await request(server)
			.get("/api/auth/.well-known/jwks.json")
			.expect(200);
		expect(response.headers["cache-control"]).toBe(DEFAULT);
	});

	it("keeps the Cache-Control Better Auth sends", async () => {
		const server = await setup(
			{},
			{
				hooks: {
					after: createAuthMiddleware(async (ctx) => {
						if (ctx.path === "/jwks")
							ctx.setHeader("Cache-Control", "no-store");
					}),
				},
			},
		);
		const response = await request(server).get("/api/auth/jwks").expect(200);
		expect(response.headers["cache-control"]).toBe("no-store");
	});

	it("leaves errors and Better Auth's other routes alone", async () => {
		const server = await setup({}, { disabledPaths: ["/jwks"] });
		const refused = await request(server).get("/api/auth/jwks");
		expect(refused.status).toBe(404);
		expect(refused.headers["cache-control"]).toBeUndefined();

		const other = await request(server).get("/api/auth/ok").expect(200);
		expect(other.headers["cache-control"]).toBeUndefined();
	});

	it.each([
		[
			"a value that isn't a header's",
			{ jwksCacheControl: "max-age=1\r\nX: y" },
			/jwksCacheControl must be a Cache-Control header value/,
		],
		["an empty one", { jwksCacheControl: " " }, /jwksCacheControl must be/],
		["true", { jwksCacheControl: true as never }, /jwksCacheControl must be/],
		[
			"a policy with routes: false",
			{ routes: false, jwksCacheControl: "no-store" },
			/routes: false doesn't/,
		],
	])("fails at startup on %s", async (_, module, message) => {
		await expect(setup(module)).rejects.toThrow(message);
	});

	it("fails at startup on a policy without jwt(), which serves no JWKS", async () => {
		await expect(
			createTestApp({
				auth: createTestAuth(),
				module: { jwksCacheControl: "no-store" },
				controllers: [],
			}),
		).rejects.toThrow(/jwt\(\) plugin, which isn't configured/);
	});

	describe("published at jwt()'s jwks.remoteUrl", () => {
		const remote = () =>
			jwt({
				jwks: {
					remoteUrl: "https://keys.example.com/.well-known/jwks.json",
					keyPairConfig: { alg: "ES256" },
				},
			});

		it("isn't served here, so gets no header", async () => {
			const server = await setup({}, { plugins: [remote()] });
			const response = await request(server).get("/api/auth/jwks");
			expect(response.status).toBe(404);
			expect(response.headers["cache-control"]).toBeUndefined();
		});

		it("fails at startup with a policy, which only its host can send", async () => {
			await expect(
				setup({ jwksCacheControl: "no-store" }, { plugins: [remote()] }),
			).rejects.toThrow(
				/publishes it at its jwks.remoteUrl \(https:\/\/keys.example.com\/.well-known\/jwks.json\)/,
			);
		});
	});

	it("doesn't need jwt() otherwise", async () => {
		({ app } = await createTestApp({
			auth: createTestAuth(),
			module: { jwksCacheControl: false },
			controllers: [],
		}));
		await request(app.getHttpServer()).get("/api/auth/ok").expect(200);
	});
});
