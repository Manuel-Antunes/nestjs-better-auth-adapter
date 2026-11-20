import { oauthProvider } from "@better-auth/oauth-provider";
import {
	Body,
	Controller,
	type INestApplication,
	Inject,
	Injectable,
	Post,
} from "@nestjs/common";
import { AuthenticationRegistry, CurrentUser } from "@nestjs/authentication";
import { jwt } from "better-auth/plugins/jwt";
import request from "supertest";
import {
	BetterAuthConfigurationError,
	BetterAuthModule,
	type BetterAuthModuleOptions,
} from "../../src/index.ts";
import {
	BetterAuthOAuthProvider,
	BetterAuthOAuthProviderModule,
} from "../../src/oauth-provider/index.ts";
import {
	TestController,
	createTestApp,
	createTestAuth,
	signUp,
} from "../shared/app.ts";

const ORIGIN = "http://localhost:3000";
const API = `${ORIGIN}/api`;

/** An app route that echoes its body, parsed by Nest's own parser. */
@Controller("echo")
class EchoController {
	@Post()
	echo(@CurrentUser("id") userId: string, @Body() body: unknown) {
		return { userId, body };
	}
}

@Injectable()
class OAuthAuth extends BetterAuthOAuthProvider {
	constructor(
		@Inject(AuthenticationRegistry) registry: AuthenticationRegistry,
	) {
		super({ audience: API });
		registry.registerProvider(this, { order: 3 });
	}
}

const createOAuthAuth = () =>
	createTestAuth({
		baseURL: ORIGIN,
		disabledPaths: ["/token"],
		plugins: [
			jwt({ disableSettingJwtHeader: true }),
			oauthProvider({
				loginPage: "/sign-in",
				consentPage: "/consent",
				scopes: ["openid", "read:post"],
				resources: [API],
			}),
		],
	});

describe("routes: false", () => {
	let app: INestApplication | undefined;

	afterEach(async () => {
		await app?.close();
		app = undefined;
	});

	it("serves none of Better Auth's routes, and still authenticates its sessions", async () => {
		const auth = createTestAuth();
		({ app } = await createTestApp({
			auth,
			module: { routes: false },
			nestBodyParser: true,
			controllers: [TestController, EchoController],
		}));
		const server = app.getHttpServer();

		await request(server).get("/api/auth/ok").expect(404);
		await request(server)
			.post("/api/auth/sign-up/email")
			.send({ name: "x", email: "x@example.com", password: "password-123456" })
			.expect(404);

		// Signed up where the routes are served: here, in-process.
		const { token, user } = await signUp(auth);
		const me = await request(server)
			.get("/test/protected")
			.set("Authorization", `Bearer ${token}`)
			.expect(200);
		expect(me.body.user.id).toBe(user.id);

		// Nest's own body parser handles the app's routes.
		const echo = await request(server)
			.post("/echo")
			.set("Authorization", `Bearer ${token}`)
			.send({ hello: "world" })
			.expect(201);
		expect(echo.body).toEqual({ userId: user.id, body: { hello: "world" } });
	});

	it("doesn't forward oauthProvider()'s discovery, but serves the resource metadata", async () => {
		({ app } = await createTestApp({
			auth: createOAuthAuth(),
			module: { routes: false },
			nestBodyParser: true,
			imports: [BetterAuthOAuthProviderModule],
			providers: [OAuthAuth],
			controllers: [],
		}));
		const server = app.getHttpServer();

		await request(server)
			.get("/.well-known/oauth-authorization-server/api/auth")
			.expect(404);
		await request(server)
			.get("/api/auth/.well-known/openid-configuration")
			.expect(404);
		// This app is still a resource server.
		const metadata = await request(server)
			.get("/.well-known/oauth-protected-resource/api")
			.expect(200);
		expect(metadata.body.resource).toBe(API);
	});

	it("works with forRootAsync()", async () => {
		const auth = createTestAuth();
		({ app } = await createTestApp({
			auth,
			betterAuthModule: BetterAuthModule.forRootAsync({
				useFactory: () => ({ auth, routes: false }),
			}),
			nestBodyParser: true,
		}));
		await request(app.getHttpServer()).get("/api/auth/ok").expect(404);
	});

	it.each([
		["bodyParser", { bodyParser: { rawBody: true } }],
		["middleware", { middleware: (_req, _res, next) => next() }],
	] satisfies [string, Omit<BetterAuthModuleOptions, "auth">][])(
		"fails at startup with %s, which only applies to Better Auth's routes",
		async (option, module) => {
			const started = createTestApp({
				auth: createTestAuth(),
				module: { ...module, routes: false },
			});
			await expect(started).rejects.toThrow(BetterAuthConfigurationError);
			await expect(started).rejects.toThrow(option);
		},
	);
});

describe("@thallesp/nestjs-better-auth's options", () => {
	it.each([
		["disableControllers", true, "routes: false"],
		["disableGlobalAuthGuard", true, "globalGuard: false"],
		["disableTrustedOriginsCors", true, "trustedOriginsCors: false"],
		["disableBodyParser", true, "enabled: false"],
		["enableRawBodyParser", false, "rawBody: true"],
	])(
		"fails at startup on %s, naming what replaces it",
		async (option, value, replacement) => {
			const started = createTestApp({
				auth: createTestAuth(),
				module: { [option]: value } as never,
			});
			await expect(started).rejects.toThrow(BetterAuthConfigurationError);
			await expect(started).rejects.toThrow(replacement);
		},
	);
});
