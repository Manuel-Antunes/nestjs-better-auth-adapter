import { Controller, Get, type INestApplication, Req } from "@nestjs/common";
import { CurrentSession, CurrentUser } from "@nestjs/authentication";
import { betterAuth } from "better-auth";
import { fromNodeHeaders } from "better-auth/node";
import { bearer } from "better-auth/plugins/bearer";
import { admin } from "better-auth/plugins/admin";
import { username } from "better-auth/plugins/username";
import request from "supertest";
import { BetterAuthService } from "../../src/index.ts";
import { nestjs } from "../../src/plugin/index.ts";
import { createTestApp, uniqueEmail } from "../shared/app.ts";

/**
 * Built with `betterAuth()` itself rather than `createTestAuth()`, so the
 * plugin and additional fields are inferred in `$Infer`.
 */
function createAuthWithCustomFields() {
	return betterAuth({
		basePath: "/api/auth",
		emailAndPassword: { enabled: true },
		logger: { disabled: true },
		plugins: [bearer(), nestjs(), username(), admin()],
		user: {
			additionalFields: {
				locale: { type: "string", required: false, defaultValue: "en" },
			},
		},
		session: {
			additionalFields: {
				deviceName: {
					type: "string",
					required: false,
					defaultValue: "unknown device",
				},
			},
		},
	});
}

type AuthWithCustomFields = ReturnType<typeof createAuthWithCustomFields>;
type User = AuthWithCustomFields["$Infer"]["Session"]["user"];
type Session = AuthWithCustomFields["$Infer"]["Session"]["session"];

@Controller("session-test")
class SessionTestController {
	constructor(
		private readonly betterAuth: BetterAuthService<AuthWithCustomFields>,
	) {}

	@Get("session")
	getSession(@CurrentUser() user: User, @CurrentSession() session: Session) {
		return { user, session };
	}

	@Get("compare")
	async compare(
		@CurrentUser() user: User,
		@CurrentSession() session: Session,
		@Req() req: { headers: Record<string, string | string[] | undefined> },
	) {
		const api = await this.betterAuth.api.getSession({
			headers: fromNodeHeaders(req.headers),
		});
		return {
			decorators: {
				username: user.username ?? null,
				displayUsername: user.displayUsername ?? null,
				role: user.role ?? null,
				locale: user.locale ?? null,
				deviceName: session.deviceName ?? null,
				sessionId: session.id,
			},
			api: {
				username: api?.user.username ?? null,
				displayUsername: api?.user.displayUsername ?? null,
				role: api?.user.role ?? null,
				locale: api?.user.locale ?? null,
				deviceName: api?.session.deviceName ?? null,
				sessionId: api?.session.id,
			},
		};
	}
}

describe("session custom fields e2e", () => {
	let app: INestApplication;
	let auth: AuthWithCustomFields;

	const signUpWithUsername = (displayUsername?: string) => {
		const name = `user_${Math.random().toString(36).slice(2, 10)}`;
		return auth.api
			.signUpEmail({
				body: {
					name: "Custom Fields",
					email: uniqueEmail(),
					password: "password-123456",
					username: name,
					...(displayUsername && { displayUsername }),
				},
			})
			.then((result) => ({ ...result, username: name }));
	};

	beforeAll(async () => {
		auth = createAuthWithCustomFields();
		({ app } = await createTestApp({
			// createTestApp is typed for createTestAuth()'s instance.
			auth: auth as never,
			controllers: [SessionTestController],
		}));
	});

	afterAll(async () => {
		await app.close();
	});

	it("should include plugin and additional user fields in @CurrentUser()", async () => {
		const { token, username: name } = await signUpWithUsername();

		const response = await request(app.getHttpServer())
			.get("/session-test/session")
			.set("Authorization", `Bearer ${token}`)
			.expect(200);

		expect(response.body.user).toMatchObject({
			username: name.toLowerCase(),
			role: "user",
			locale: "en",
		});
		expect(response.body.user).toHaveProperty("id");
		expect(response.body.user).toHaveProperty("email");
	});

	it("should include displayUsername in @CurrentUser()", async () => {
		const { token } = await signUpWithUsername("Display_Name");

		const response = await request(app.getHttpServer())
			.get("/session-test/session")
			.set("Authorization", `Bearer ${token}`)
			.expect(200);

		expect(response.body.user.displayUsername).toBe("Display_Name");
	});

	it("should include additional session fields in @CurrentSession()", async () => {
		const { token, user } = await signUpWithUsername();

		const response = await request(app.getHttpServer())
			.get("/session-test/session")
			.set("Authorization", `Bearer ${token}`)
			.expect(200);

		expect(response.body.session).toMatchObject({
			userId: user.id,
			deviceName: "unknown device",
		});
	});

	it("should return the same fields as betterAuth.api.getSession()", async () => {
		const { token, username: name } = await signUpWithUsername("Shown");

		const response = await request(app.getHttpServer())
			.get("/session-test/compare")
			.set("Authorization", `Bearer ${token}`)
			.expect(200);

		expect(response.body.decorators).toEqual(response.body.api);
		expect(response.body.decorators).toMatchObject({
			username: name.toLowerCase(),
			displayUsername: "Shown",
			deviceName: "unknown device",
		});
	});
});
