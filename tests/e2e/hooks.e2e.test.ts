import { type INestApplication, Injectable } from "@nestjs/common";
import { betterAuth } from "better-auth";
import request from "supertest";
import {
	AfterHook,
	type AuthHookContext,
	BeforeHook,
	BetterAuthService,
	Hook,
} from "../../src/index.ts";
import { createTestApp, createTestAuth, uniqueEmail } from "../shared/app.ts";

@Injectable()
class HookTracker {
	calls: string[] = [];
}

@Hook()
@Injectable()
class SignUpHooks {
	constructor(private readonly tracker: HookTracker) {}

	@BeforeHook("/sign-up/email")
	async before(_ctx: AuthHookContext) {
		this.tracker.calls.push("before /sign-up/email");
	}

	@AfterHook("/sign-up/email")
	async after(_ctx: AuthHookContext) {
		this.tracker.calls.push("after /sign-up/email");
	}
}

@Hook()
@Injectable()
class EveryRouteHook {
	constructor(private readonly tracker: HookTracker) {}

	@BeforeHook()
	async before(ctx: AuthHookContext) {
		this.tracker.calls.push(`any ${ctx.path}`);
	}
}

@Hook()
@Injectable()
class ResponseHook {
	@AfterHook("/ok")
	async replace(ctx: AuthHookContext) {
		return ctx.json({ hooked: true });
	}
}

const signUpBody = () => ({
	name: "Hook User",
	email: uniqueEmail(),
	password: "password-123456",
});

describe("hooks e2e", () => {
	let app: INestApplication;

	beforeAll(async () => {
		// No `hooks: {}` in the config: hooks run through the nestjs() plugin.
		({ app } = await createTestApp({
			auth: createTestAuth(),
			providers: [HookTracker, SignUpHooks, EveryRouteHook, ResponseHook],
		}));
	});

	afterAll(async () => {
		await app.close();
	});

	beforeEach(() => {
		app.get(HookTracker).calls = [];
	});

	it("should call @BeforeHook and @AfterHook on the matching route", async () => {
		await request(app.getHttpServer())
			.post("/api/auth/sign-up/email")
			.send(signUpBody())
			.expect(200);

		expect(app.get(HookTracker).calls).toEqual(
			expect.arrayContaining(["before /sign-up/email", "after /sign-up/email"]),
		);
	});

	it("should not call path hooks on other routes", async () => {
		await request(app.getHttpServer()).get("/api/auth/ok").expect(200);

		expect(app.get(HookTracker).calls).toEqual(["any /ok"]);
	});

	it("should call a hook without a path on every route", async () => {
		await request(app.getHttpServer())
			.post("/api/auth/sign-up/email")
			.send(signUpBody())
			.expect(200);

		expect(app.get(HookTracker).calls).toContain("any /sign-up/email");
	});

	it("should replace the response with an @AfterHook's return value", async () => {
		const response = await request(app.getHttpServer())
			.get("/api/auth/ok")
			.expect(200);

		expect(response.body).toEqual({ hooked: true });
	});

	it("should run hooks for server-side API calls too", async () => {
		await app.get(BetterAuthService).api.signUpEmail({ body: signUpBody() });

		expect(app.get(HookTracker).calls).toEqual(
			expect.arrayContaining(["before /sign-up/email", "after /sign-up/email"]),
		);
	});
});

describe("hooks configuration validation", () => {
	it("should fail at startup when the auth instance lacks the nestjs() plugin", async () => {
		const auth = betterAuth({
			basePath: "/api/auth",
			emailAndPassword: { enabled: true },
			logger: { disabled: true },
		});

		await expect(
			createTestApp({
				auth: auth as never,
				providers: [HookTracker, SignUpHooks],
			}),
		).rejects.toThrow("needs Better Auth's nestjs() plugin");
	});
});

describe("hooks e2e: an auth instance reused by another app", () => {
	it("runs each hook once, on the live app's provider", async () => {
		const auth = createTestAuth();
		const first = await createTestApp({
			auth,
			controllers: [],
			providers: [HookTracker, SignUpHooks],
		});
		const firstTracker = first.app.get(HookTracker);
		await first.app.close();

		const second = await createTestApp({
			auth,
			controllers: [],
			providers: [HookTracker, SignUpHooks],
		});
		try {
			await request(second.app.getHttpServer())
				.post("/api/auth/sign-up/email")
				.send(signUpBody())
				.expect(200);

			expect(second.app.get(HookTracker).calls).toEqual([
				"before /sign-up/email",
				"after /sign-up/email",
			]);
			expect(firstTracker.calls).toEqual([]);
		} finally {
			await second.app.close();
		}
	});
});
