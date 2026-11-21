import { Controller, Get, Injectable } from "@nestjs/common";
import {
	ApiKeyProvider,
	Authenticate,
	AuthenticationContext,
} from "@nestjs/authentication";
import { Can } from "@nestjs/authorization";
import { getDrizzleToken } from "@nestjs/drizzle";
import { Test } from "@nestjs/testing";
import {
	BetterAuthJwtProvider,
	BetterAuthService,
	BetterAuthSessionProvider,
} from "nestjs-better-auth-adapter";
import request from "supertest";
import { AppModule } from "../src/app.module.ts";
import { createHttpAdapter, setupApp } from "../src/app.setup.ts";
import type { Auth } from "../src/auth/create-auth.ts";
import type { Database } from "../src/database/create-database.ts";
import { Mailer } from "../src/mail/mailer.ts";
import { InMemoryMailer } from "./support/in-memory.mailer.ts";
import { adapter, type TestApp } from "./support/test-app.ts";
import {
	createOrganization,
	enrollAndStepUp,
	PASSWORD,
	signUp,
	signUpVerified,
} from "./support/users.ts";

/** A singleton, like any app service: it never sees the request. */
@Injectable()
class ProbeService {
	constructor(private readonly auth: AuthenticationContext) {}

	read() {
		return {
			isAuthenticated: this.auth.isAuthenticated,
			userId: this.auth.user?.id ?? null,
			email: this.auth.user?.email ?? null,
			session: this.auth.session,
			required: this.auth.requireUser().id,
		};
	}

	readAfterAwait() {
		return new Promise((resolve) => setTimeout(() => resolve(this.read()), 20));
	}
}

@Controller("probe")
class ProbeController {
	constructor(private readonly probe: ProbeService) {}

	@Get("any")
	@Can.Anyone()
	any() {
		return this.probe.read();
	}

	@Get("session")
	@Authenticate({ providers: [BetterAuthSessionProvider] })
	@Can.Anyone()
	session() {
		return this.probe.readAfterAwait();
	}

	@Get("jwt")
	@Authenticate({ providers: [BetterAuthJwtProvider] })
	@Can.Anyone()
	jwt() {
		return this.probe.readAfterAwait();
	}

	@Get("api-key")
	@Authenticate({ providers: [ApiKeyProvider] })
	@Can.Anyone()
	apiKey() {
		return this.probe.readAfterAwait();
	}
}

describe("AuthenticationContext in a singleton, per credential provider", () => {
	let t: TestApp;

	beforeAll(async () => {
		const moduleRef = await Test.createTestingModule({
			imports: [AppModule],
			controllers: [ProbeController],
			providers: [ProbeService],
		})
			.overrideProvider(Mailer)
			.useClass(InMemoryMailer)
			.compile();
		const app = moduleRef.createNestApplication(createHttpAdapter(adapter), {
			bodyParser: false,
			logger: ["error"],
		});
		await setupApp(app);
		await app.init();
		if (adapter === "fastify") await app.getHttpAdapter().getInstance().ready();
		t = {
			app,
			http: () => request(app.getHttpServer()),
			mailer: app.get(Mailer) as InMemoryMailer,
			auth: app.get(BetterAuthService<Auth>).instance,
			db: app.get<Database>(getDrizzleToken()),
		} as TestApp;
	});
	afterAll(async () => {
		await t.app.close();
	});

	it("session via Bearer token: user and the session row (activeOrganizationId, mfaVerifiedAt)", async () => {
		const user = await signUp(t);
		const { body } = await t
			.http()
			.get("/api/v1/probe/session")
			.set("Authorization", user.bearer)
			.expect(200);
		expect(body).toMatchObject({
			isAuthenticated: true,
			userId: user.id,
			email: user.email,
			required: user.id,
		});
		expect(body.session).toMatchObject({ userId: user.id });
		expect(body.session).toHaveProperty("id");
		console.log("session (bearer):", JSON.stringify(body.session));
	});

	it("the active organization reaches session.activeOrganizationId, and the next JWT's claims", async () => {
		const owner = await signUpVerified(t);
		const org = await createOrganization(t, owner, "Initech");

		const viaSession = await t
			.http()
			.get("/api/v1/probe/session")
			.set("Authorization", owner.bearer)
			.expect(200);
		expect(viaSession.body.session.activeOrganizationId).toBe(org.id);

		const jwt = (
			await t
				.http()
				.get("/api/auth/token")
				.set("Authorization", owner.bearer)
				.expect(200)
		).body.token as string;
		const viaJwt = await t
			.http()
			.get("/api/v1/probe/jwt")
			.set("Authorization", `Bearer ${jwt}`)
			.expect(200);
		expect(viaJwt.body.session.activeOrganizationId).toBe(org.id);

		// And the app's own services, through the same context, on both transports.
		await t
			.http()
			.get("/api/v1/projects")
			.set("Authorization", owner.bearer)
			.expect(200);
		await t
			.http()
			.get("/api/v1/internal/projects")
			.set("Authorization", `Bearer ${jwt}`)
			.expect(200);
	});

	it("session via cookie", async () => {
		const user = await signUp(t);
		const signIn = await t
			.http()
			.post("/api/auth/sign-in/email")
			.send({ email: user.email, password: PASSWORD })
			.expect(200);
		const cookie = (signIn.headers["set-cookie"] as unknown as string[]).map(
			(c) => c.split(";")[0],
		);
		const { body } = await t
			.http()
			.get("/api/v1/probe/session")
			.set("Cookie", cookie)
			.expect(200);
		expect(body).toMatchObject({ userId: user.id, isAuthenticated: true });
		expect(body.session).toMatchObject({ userId: user.id });
	});

	it("JWT: user and the token's claims", async () => {
		const user = await signUp(t);
		const token = (
			await t
				.http()
				.get("/api/auth/token")
				.set("Authorization", user.bearer)
				.expect(200)
		).body.token as string;
		const { body } = await t
			.http()
			.get("/api/v1/probe/jwt")
			.set("Authorization", `Bearer ${token}`)
			.expect(200);
		expect(body).toMatchObject({
			isAuthenticated: true,
			userId: user.id,
			email: user.email,
			required: user.id,
		});
		expect(body.session).toMatchObject({ sub: user.id, email: user.email });
		expect(body.session).toHaveProperty("activeOrganizationId");
		console.log("session (jwt claims):", JSON.stringify(body.session));
	});

	it("API key: user and the key's session", async () => {
		const user = await signUpVerified(t);
		await enrollAndStepUp(t, user);
		const created = await t
			.http()
			.post("/api/auth/api-key/create")
			.set("Authorization", user.bearer)
			.send({ name: "ci", expiresIn: 30 * 24 * 60 * 60 })
			.expect(200);
		const { body } = await t
			.http()
			.get("/api/v1/probe/api-key")
			.set("x-api-key", created.body.key)
			.expect(200);
		expect(body).toMatchObject({
			isAuthenticated: true,
			userId: user.id,
			email: user.email,
			required: user.id,
		});
		expect(body.session).toMatchObject({ method: "api-key" });
		console.log("session (api key):", JSON.stringify(body.session));
	});

	it("anonymous: empty context, requireUser() is a 401", async () => {
		const res = await t.http().get("/api/v1/probe/any").expect(401);
		expect(res.body.userId ?? null).toBeNull();
	});

	it("concurrent requests of different users never see each other", async () => {
		const users = await Promise.all(Array.from({ length: 8 }, () => signUp(t)));
		const results = await Promise.all(
			users.map((u) =>
				t
					.http()
					.get("/api/v1/probe/session")
					.set("Authorization", u.bearer)
					.then((r) => ({ expected: u.id, got: r.body.userId })),
			),
		);
		for (const r of results) expect(r.got).toBe(r.expected);
	});
});
