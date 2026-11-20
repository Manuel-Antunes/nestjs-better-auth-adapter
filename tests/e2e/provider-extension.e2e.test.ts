import { Inject, Injectable, Module } from "@nestjs/common";
import { AuthenticationRegistry } from "@nestjs/authentication";
import { apiKey } from "@better-auth/api-key";
import { admin } from "better-auth/plugins/admin";
import { jwt } from "better-auth/plugins/jwt";
import { io as ioc } from "socket.io-client";
import request from "supertest";
import {
	type BetterAuthApiKey,
	BetterAuthApiKeyProvider,
	type BetterAuthJwtClaims,
	BetterAuthJwtProvider,
	BetterAuthSessionProvider,
	type BetterAuthUser,
} from "../../src/index.ts";
import {
	createTestApp,
	createTestAuth,
	signUp,
	TestGateway,
	type TestAuth,
	verifyEmail,
} from "../shared/app.ts";
import { ApiKeyAuth, JwtAuth, SessionAuth } from "../shared/auth-providers.ts";

const BASE_URL = "http://localhost:3000";

/** Refuses sessions of users who haven't verified their address. */
@Injectable()
class VerifiedSessionAuth extends BetterAuthSessionProvider {
	constructor(
		@Inject(AuthenticationRegistry) registry: AuthenticationRegistry,
	) {
		super();
		registry.registerProvider(this, { order: 0 });
	}

	protected override validate(user: BetterAuthUser) {
		return user.emailVerified ? user : null;
	}
}

/** Accepts the keys named `partner` only. */
@Injectable()
class PartnerApiKeyAuth extends BetterAuthApiKeyProvider {
	constructor(
		@Inject(AuthenticationRegistry) registry: AuthenticationRegistry,
	) {
		super();
		registry.registerProvider(this, { order: 2 });
	}

	protected override async validate(key: BetterAuthApiKey) {
		if (key.name !== "partner") return null;
		return super.validate(key);
	}
}

/** Refuses the users named `Blocked`, in its own realm. */
@Injectable()
class BlockingJwtAuth extends BetterAuthJwtProvider {
	constructor(
		@Inject(AuthenticationRegistry) registry: AuthenticationRegistry,
	) {
		super({ realm: "partners" });
		registry.registerProvider(this, { order: 1 });
	}

	protected override async validate(payload: BetterAuthJwtClaims) {
		const user = await super.validate(payload);
		return user?.name === "Blocked" ? null : user;
	}
}

// biome-ignore lint/suspicious/noExplicitAny: the plugin endpoints are not typed on the generic auth instance
const api = (auth: TestAuth) => auth.api as any;

/** A JWT of the `jwt()` plugin for the session behind `token`. */
async function jwtFor(auth: TestAuth, token: string): Promise<string> {
	const result = await api(auth).getToken({
		headers: new Headers({ Authorization: `Bearer ${token}` }),
	});
	return result.token;
}

describe("provider subclasses", () => {
	it("run their validate(), and still match @Authenticate({ providers })", async () => {
		const auth = createTestAuth();
		const { app } = await createTestApp({
			auth,
			authProviders: [VerifiedSessionAuth],
		});

		try {
			const { token, user } = await signUp(auth);
			const refused = await request(app.getHttpServer())
				.get("/test/protected")
				.set("Authorization", `Bearer ${token}`)
				.expect(401);
			expect(refused.body.errorCode).toBe("invalid_session");

			await verifyEmail(auth, user.id);
			await request(app.getHttpServer())
				.get("/test/protected")
				.set("Authorization", `Bearer ${token}`)
				.expect(200);
			// @Authenticate({ providers: [BetterAuthSessionProvider] }) covers it.
			await request(app.getHttpServer())
				.get("/test/session-only")
				.set("Authorization", `Bearer ${token}`)
				.expect(200);
		} finally {
			await app.close();
		}
	});

	it("live in any module of the app", async () => {
		@Module({ providers: [PartnerApiKeyAuth] })
		class PartnerModule {}

		const auth = createTestAuth({ plugins: [apiKey()] });
		const { app } = await createTestApp({
			auth,
			authProviders: [SessionAuth],
			imports: [PartnerModule],
		});

		try {
			const { user } = await signUp(auth);
			const partner = await api(auth).createApiKey({
				body: { userId: user.id, name: "partner" },
			});
			const other = await api(auth).createApiKey({
				body: { userId: user.id, name: "other" },
			});

			const response = await request(app.getHttpServer())
				.get("/test/protected")
				.set("x-api-key", partner.key)
				.expect(200);
			expect(response.body.user.id).toBe(user.id);
			await request(app.getHttpServer())
				.get("/test/protected")
				.set("x-api-key", other.key)
				.expect(401);
		} finally {
			await app.close();
		}
	});

	it("keep super.validate(), with the options they pass to super()", async () => {
		const auth = createTestAuth({ baseURL: BASE_URL, plugins: [jwt()] });
		const { app } = await createTestApp({
			auth,
			authProviders: [SessionAuth, BlockingJwtAuth],
		});

		try {
			const allowed = await signUp(auth);
			const blocked = await signUp(auth, { name: "Blocked" });

			const response = await request(app.getHttpServer())
				.get("/test/protected")
				.set(
					"Authorization",
					`Bearer ${await jwtFor(auth, allowed.token ?? "")}`,
				)
				.expect(200);
			expect(response.body.user.id).toBe(allowed.user.id);

			const refused = await request(app.getHttpServer())
				.get("/test/protected")
				.set(
					"Authorization",
					`Bearer ${await jwtFor(auth, blocked.token ?? "")}`,
				)
				.expect(401);
			expect(refused.headers["www-authenticate"]).toContain('realm="partners"');
		} finally {
			await app.close();
		}
	});

	it("fail at startup without their plugin", async () => {
		await expect(
			createTestApp({ auth: createTestAuth(), authProviders: [JwtAuth] }),
		).rejects.toThrow(
			"JwtAuth verifies the JWTs of Better Auth's jwt() plugin",
		);
		await expect(
			createTestApp({ auth: createTestAuth(), authProviders: [ApiKeyAuth] }),
		).rejects.toThrow("ApiKeyAuth verifies the keys of Better Auth's apiKey()");
	});
});

describe("banned users (admin plugin)", () => {
	let auth: TestAuth;
	let app: Awaited<ReturnType<typeof createTestApp>>["app"];

	beforeAll(async () => {
		auth = createTestAuth({
			baseURL: BASE_URL,
			plugins: [admin(), apiKey(), jwt()],
		});
		({ app } = await createTestApp({ auth }));
	});

	afterAll(async () => {
		await app.close();
	});

	/** Bans the user in the database, as `banUser` does, but keeps their sessions. */
	async function ban(userId: string, banExpires: Date | null = null) {
		const ctx = await auth.$context;
		await ctx.internalAdapter.updateUser(userId, { banned: true, banExpires });
	}

	it("refuses their API keys, JWTs and sessions with a 403", async () => {
		const { user, token } = await signUp(auth);
		const key = await api(auth).createApiKey({
			body: { userId: user.id, name: "ci" },
		});
		const jwtToken = await jwtFor(auth, token ?? "");
		await ban(user.id);

		for (const [header, value] of [
			["x-api-key", key.key],
			["Authorization", `Bearer ${jwtToken}`],
			["Authorization", `Bearer ${token}`],
		] as const) {
			const response = await request(app.getHttpServer())
				.get("/test/protected")
				.set(header, value)
				.expect(403);
			expect(response.body.errorCode).toBe("banned_user");
		}
	});

	it("lets them in once the ban expired", async () => {
		const { user } = await signUp(auth);
		const key = await api(auth).createApiKey({
			body: { userId: user.id, name: "ci" },
		});
		await ban(user.id, new Date(Date.now() - 1000));

		await request(app.getHttpServer())
			.get("/test/protected")
			.set("x-api-key", key.key)
			.expect(200);
	});
});

describe("session cookies", () => {
	it("sends the cookies getSession() refreshes", async () => {
		const auth = createTestAuth({
			// Refreshed on every request, and cached in a cookie.
			session: { updateAge: 0, cookieCache: { enabled: true } },
		});
		const { app } = await createTestApp({ auth });

		try {
			const { token } = await signUp(auth);
			const response = await request(app.getHttpServer())
				.get("/test/protected")
				.set("Authorization", `Bearer ${token}`)
				.expect(200);

			const cookies = ([] as string[]).concat(
				response.headers["set-cookie"] ?? [],
			);
			expect(cookies.some((c) => c.includes("session_token="))).toBe(true);
			expect(cookies.some((c) => c.includes("session_data="))).toBe(true);
		} finally {
			await app.close();
		}
	});
});

describe("jwt provider", () => {
	it("refuses to start when the issuer and audience can't be checked", async () => {
		await expect(
			createTestApp({ auth: createTestAuth({ plugins: [jwt()] }) }),
		).rejects.toThrow("needs the JWT issuer and audience checked");
	});

	it("reads socket.io's handshake.auth.token", async () => {
		const auth = createTestAuth({ baseURL: BASE_URL, plugins: [jwt()] });
		const { app } = await createTestApp({
			auth,
			providers: [TestGateway],
			listen: true,
		});
		const url = `http://localhost:${app.getHttpServer().address().port}/test`;
		const { token } = await signUp(auth, { name: "Socket User" });
		const socket = ioc(url, {
			path: "/ws",
			auth: { token: await jwtFor(auth, token ?? "") },
		});

		try {
			await new Promise<void>((resolve) => socket.once("connect", resolve));
			const reply = new Promise((resolve) => socket.once("protected", resolve));
			socket.emit("protected");
			expect(await reply).toBe("Socket User");
		} finally {
			socket.disconnect();
			app.getHttpServer().closeAllConnections?.();
			await app.close();
		}
	});
});
