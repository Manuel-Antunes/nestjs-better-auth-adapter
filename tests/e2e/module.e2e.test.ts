import { Injectable, Module } from "@nestjs/common";
import request from "supertest";
import {
	BetterAuthModule,
	type BetterAuthModuleOptions,
	type BetterAuthOptionsFactory,
	BetterAuthService,
} from "../../src/index.ts";
import {
	createTestApp,
	createTestAuth,
	uniqueEmail,
	type TestAuth,
} from "../shared/app.ts";

const AUTH = Symbol("AUTH");

/** Provides the auth instance to the async factories, as a config module would. */
@Module({})
class AuthConfigModule {
	static with(auth: TestAuth) {
		return {
			module: AuthConfigModule,
			providers: [{ provide: AUTH, useValue: auth }],
			exports: [AUTH],
		};
	}
}

/** `useClass` options factory, like `GqlOptionsFactory`. */
@Injectable()
class BetterAuthConfig implements BetterAuthOptionsFactory {
	static auth: TestAuth;
	createBetterAuthOptions(): BetterAuthModuleOptions {
		return { auth: BetterAuthConfig.auth };
	}
}

/** Signs up through Better Auth's route, then calls a protected route with the token. */
async function expectServesAndAuthenticates(server: unknown) {
	const signUp = await request(server as never)
		.post("/api/auth/sign-up/email")
		.send({
			name: "Async User",
			email: uniqueEmail(),
			password: "password-123456",
		})
		.expect(200);

	const response = await request(server as never)
		.get("/test/protected")
		.set("Authorization", `Bearer ${signUp.body.token}`)
		.expect(200);
	expect(response.body.user.id).toBe(signUp.body.user.id);
}

describe("module e2e", () => {
	it("works with forRoot()", async () => {
		const { app } = await createTestApp({ auth: createTestAuth() });
		try {
			await expectServesAndAuthenticates(app.getHttpServer());
		} finally {
			await app.close();
		}
	});

	it("works with forRootAsync({ useFactory, inject })", async () => {
		const auth = createTestAuth();
		const { app, moduleRef } = await createTestApp({
			auth,
			betterAuthModule: BetterAuthModule.forRootAsync({
				imports: [AuthConfigModule.with(auth)],
				inject: [AUTH],
				useFactory: async (injected: TestAuth) => ({ auth: injected }),
			}),
		});
		try {
			await expectServesAndAuthenticates(app.getHttpServer());
			expect(moduleRef.get(BetterAuthService).instance).toBe(auth);
		} finally {
			await app.close();
		}
	});

	it("works with forRootAsync({ useClass }) and BetterAuthOptionsFactory", async () => {
		const auth = createTestAuth();
		BetterAuthConfig.auth = auth;
		const { app, moduleRef } = await createTestApp({
			auth,
			betterAuthModule: BetterAuthModule.forRootAsync({
				useClass: BetterAuthConfig,
			}),
		});
		try {
			await expectServesAndAuthenticates(app.getHttpServer());
			expect(moduleRef.get(BetterAuthService).instance).toBe(auth);
		} finally {
			await app.close();
		}
	});
});
