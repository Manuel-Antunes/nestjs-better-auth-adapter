import { type INestApplication, Injectable } from "@nestjs/common";
import { betterAuth } from "better-auth";
import request from "supertest";
import {
	AfterCreate,
	AfterUpdate,
	BeforeCreate,
	DatabaseHook,
} from "../../src/index.ts";
import {
	createTestApp,
	createTestAuth,
	signUp,
	uniqueEmail,
	type TestAuth,
} from "../shared/app.ts";

@Injectable()
class DatabaseHookTracker {
	calls: { hook: string; model: string; operation: string }[] = [];

	track(hook: string, model: string, operation: string) {
		this.calls.push({ hook, model, operation });
	}

	count(hook: string, model: string, operation: string) {
		return this.calls.filter(
			(c) => c.hook === hook && c.model === model && c.operation === operation,
		).length;
	}
}

@DatabaseHook()
@Injectable()
class UserDatabaseHook {
	constructor(private readonly tracker: DatabaseHookTracker) {}

	@BeforeCreate("user")
	async beforeCreate(user: { email: string; name: string }) {
		this.tracker.track("before", "user", "create");
		if (user.email.startsWith("blocked-")) return false;
		if (user.email.startsWith("renamed-"))
			return { data: { name: `${user.name} (renamed)` } };
	}

	@AfterCreate("user")
	async afterCreate() {
		this.tracker.track("after", "user", "create");
	}

	@AfterUpdate("user")
	async afterUpdate() {
		this.tracker.track("after", "user", "update");
	}
}

@DatabaseHook()
@Injectable()
class SessionDatabaseHook {
	constructor(private readonly tracker: DatabaseHookTracker) {}

	@AfterCreate("session")
	async afterCreate() {
		this.tracker.track("after", "session", "create");
	}
}

/** A second `@BeforeCreate('user')` provider, chained after the first. */
@DatabaseHook()
@Injectable()
class SecondUserDatabaseHook {
	@BeforeCreate("user")
	async beforeCreate(user: { email: string; name: string }) {
		if (user.email.startsWith("renamed-"))
			return { data: { name: `${user.name} twice` } };
	}
}

const signUpRequest = (app: INestApplication, email = uniqueEmail()) =>
	request(app.getHttpServer())
		.post("/api/auth/sign-up/email")
		.send({ name: "Db User", email, password: "password-123456" });

describe("database hooks e2e", () => {
	let app: INestApplication;
	let auth: TestAuth;
	let tracker: DatabaseHookTracker;

	beforeAll(async () => {
		// No `databaseHooks: {}` in the config: they run through the nestjs() plugin.
		auth = createTestAuth();
		({ app } = await createTestApp({
			auth,
			providers: [
				DatabaseHookTracker,
				UserDatabaseHook,
				SessionDatabaseHook,
				SecondUserDatabaseHook,
			],
		}));
		tracker = app.get(DatabaseHookTracker);
	});

	afterAll(async () => {
		await app.close();
	});

	it("should call @BeforeCreate('user') and @AfterCreate('user') on sign-up", async () => {
		const before = tracker.count("before", "user", "create");
		const after = tracker.count("after", "user", "create");

		await signUpRequest(app).expect(200);

		expect(tracker.count("before", "user", "create")).toBe(before + 1);
		expect(tracker.count("after", "user", "create")).toBe(after + 1);
	});

	it("should call @AfterCreate('session') on sign-up", async () => {
		const before = tracker.count("after", "session", "create");

		await signUpRequest(app).expect(200);

		expect(tracker.count("after", "session", "create")).toBe(before + 1);
	});

	it("should call @AfterUpdate('user') on update", async () => {
		const before = tracker.count("after", "user", "update");
		const { user } = await signUp(auth);

		const ctx = await auth.$context;
		await ctx.internalAdapter.updateUser(user.id, { name: "Updated" });

		expect(tracker.count("after", "user", "update")).toBe(before + 1);
	});

	it("should let a @BeforeCreate change the record with { data }, chaining providers", async () => {
		const email = `renamed-${uniqueEmail()}`;
		const response = await signUpRequest(app, email).expect(200);

		expect(response.body.user.name).toBe("Db User (renamed) twice");
		const ctx = await auth.$context;
		const stored = await ctx.internalAdapter.findUserByEmail(email);
		expect(stored?.user.name).toBe("Db User (renamed) twice");
	});

	it("should let a @BeforeCreate cancel the write by returning false", async () => {
		const email = `blocked-${uniqueEmail()}`;
		const response = await signUpRequest(app, email);

		expect(response.status).toBeGreaterThanOrEqual(400);
		const ctx = await auth.$context;
		expect(await ctx.internalAdapter.findUserByEmail(email)).toBeNull();
	});
});

describe("database hooks configuration validation", () => {
	it("should fail at startup when the auth instance lacks the nestjs() plugin", async () => {
		const auth = betterAuth({
			basePath: "/api/auth",
			emailAndPassword: { enabled: true },
			logger: { disabled: true },
		});

		await expect(
			createTestApp({
				auth: auth as never,
				providers: [DatabaseHookTracker, UserDatabaseHook],
			}),
		).rejects.toThrow("needs Better Auth's nestjs() plugin");
	});
});
