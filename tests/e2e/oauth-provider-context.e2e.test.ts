import { oauthProvider } from "@better-auth/oauth-provider";
import { Controller, Get, Inject, Injectable } from "@nestjs/common";
import {
	AuthenticationContext,
	AuthenticationRegistry,
} from "@nestjs/authentication";
import { jwt } from "better-auth/plugins/jwt";
import request from "supertest";
import {
	type BetterAuthOAuthAccessToken,
	BetterAuthOAuthProvider,
	BetterAuthOAuthProviderModule,
	OAuthScopes,
} from "../../src/oauth-provider/index.ts";
import { createTestApp, createTestAuth } from "../shared/app.ts";
import { oauthFlows } from "../shared/oauth.ts";

const ORIGIN = "http://localhost:3000";
const ISSUER = `${ORIGIN}/api/auth`;
const API = `${ORIGIN}/api`;

@Injectable()
class OAuthAuth extends BetterAuthOAuthProvider {
	constructor(
		@Inject(AuthenticationRegistry) registry: AuthenticationRegistry,
	) {
		super({ audience: API });
		registry.registerProvider(this, { order: 3 });
	}
}

/** A singleton, like any app service: it never sees the request. */
@Injectable()
class ScopesService {
	constructor(
		private readonly auth: AuthenticationContext<
			unknown,
			BetterAuthOAuthAccessToken
		>,
	) {}

	granted() {
		return new Promise<string[]>((resolve) =>
			setTimeout(() => resolve(this.auth.session?.scopes ?? []), 10),
		);
	}
}

@Controller("api")
class ProbeController {
	constructor(private readonly scopes: ScopesService) {}

	@OAuthScopes("read:post")
	@Get("granted")
	async granted() {
		return { scopes: await this.scopes.granted() };
	}
}

describe("OAuth scopes read through AuthenticationContext", () => {
	let app: Awaited<ReturnType<typeof createTestApp>>["app"];
	let auth: ReturnType<typeof createAuth>;
	const createAuth = () =>
		createTestAuth({
			baseURL: ORIGIN,
			disabledPaths: ["/token"],
			plugins: [
				jwt({
					disableSettingJwtHeader: true,
					jwt: { issuer: ISSUER, audience: API },
				}),
				oauthProvider({
					loginPage: "/sign-in",
					consentPage: "/consent",
					scopes: [
						"openid",
						"profile",
						"email",
						"offline_access",
						"read:post",
						"write:post",
					],
					resources: [API],
					clientRegistrationDefaultResources: [API],
					clientPrivileges: () => true,
				}),
			],
		});

	beforeAll(async () => {
		auth = createAuth();
		({ app } = await createTestApp({
			auth,
			imports: [BetterAuthOAuthProviderModule],
			providers: [OAuthAuth, ScopesService],
			controllers: [ProbeController],
		}));
	});
	afterAll(async () => {
		await app.close();
	});

	it("session.scopes is what the user granted, in a singleton, after an await", async () => {
		const { signIn, createClient, authorize } = oauthFlows({
			server: () => app.getHttpServer(),
			auth: () => auth,
			issuer: ISSUER,
		});
		const user = await signIn();
		const client = await createClient(user.cookie, {
			scope: "openid profile read:post write:post",
		});
		const { access_token } = await authorize(user, client, {
			scope: "openid read:post write:post",
			resource: API,
		});
		const response = await request(app.getHttpServer())
			.get("/api/granted")
			.set("Authorization", `Bearer ${access_token}`);
		expect(response.status).toBe(200);
		expect(response.body.scopes).toEqual(["openid", "read:post", "write:post"]);
	});
});
