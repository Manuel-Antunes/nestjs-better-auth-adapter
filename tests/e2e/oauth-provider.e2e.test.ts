import { createHash, randomBytes } from "node:crypto";
import { oauthProvider } from "@better-auth/oauth-provider";
import {
	type ArgumentsHost,
	Catch,
	Controller,
	type ExceptionFilter,
	Get,
	type HttpException,
	Inject,
	Injectable,
	UseFilters,
} from "@nestjs/common";
import {
	Authenticate,
	AuthenticationError,
	AuthenticationRegistry,
	CurrentSession,
	CurrentUser,
	type JwtClaims,
} from "@nestjs/authentication";
import { admin } from "better-auth/plugins/admin";
import { jwt } from "better-auth/plugins/jwt";
import request from "supertest";
import {
	type BetterAuthOAuthAccessToken,
	BetterAuthOAuthProvider,
	BetterAuthOAuthProviderModule,
	type BetterAuthOAuthProviderOptions,
	OAuthAccessTokenError,
	OAuthAccessTokenNotAcceptedError,
	OAuthInsufficientScopeError,
	OAuthScopes,
} from "../../src/oauth-provider/index.ts";
import { createTestApp, createTestAuth, uniqueEmail } from "../shared/app.ts";
import {
	REDIRECT,
	dpopKey,
	type OAuthApi,
	type OAuthClient,
	oauthFlows,
} from "../shared/oauth.ts";

const ORIGIN = "http://localhost:3000";
const ISSUER = `${ORIGIN}/api/auth`;
/** This API, as a resource server. */
const API = `${ORIGIN}/api`;
/** Another resource this app serves: its MCP endpoint. */
const MCP = `${ORIGIN}/mcp`;
const METADATA = `${ORIGIN}/.well-known/oauth-protected-resource/api`;

/** The app's OAuth provider for `options`, registered at `order`. */
function oauthAuth(options: BetterAuthOAuthProviderOptions, order = 3) {
	@Injectable()
	class OAuthAuth extends BetterAuthOAuthProvider {
		constructor(
			@Inject(AuthenticationRegistry) registry: AuthenticationRegistry,
		) {
			super(options);
			registry.registerProvider(this, { order });
		}
	}
	return OAuthAuth;
}

/** What a `client_credentials` token stands for, in the app below. */
type ClientPrincipal = { kind: "client"; clientId: string };
/** The app's own view of a user, without Better Auth's `banned` field. */
type AppUser = { kind: "user"; id: string };

/**
 * An API that also admits `client_credentials` tokens, on the routes that
 * ask for it, with principals of its own.
 */
@Injectable()
class MachineOAuthAuth extends BetterAuthOAuthProvider<
	ClientPrincipal | AppUser
> {
	constructor(
		@Inject(AuthenticationRegistry) registry: AuthenticationRegistry,
	) {
		// OAuthAuth serves this audience's metadata.
		super({ audience: API, resourceMetadata: false });
		registry.registerProvider(this, { order: 9 });
	}

	protected override async validate(
		claims: JwtClaims,
	): Promise<ClientPrincipal | AppUser | null> {
		if (this.isClientCredentials(claims))
			return { kind: "client", clientId: String(claims.azp) };
		const user = await super.validate(claims);
		return user && "id" in user ? { kind: "user", id: user.id } : null;
	}
}

/** A resource server of both identifiers, on the routes that ask for it. */
@Injectable()
class BothAudiencesAuth extends BetterAuthOAuthProvider {
	constructor(
		@Inject(AuthenticationRegistry) registry: AuthenticationRegistry,
	) {
		super({ audience: [API, MCP], resourceMetadata: false });
		registry.registerProvider(this, { order: 10 });
	}
}

@Controller("mcp")
class McpController {
	@Authenticate({ providers: [BothAudiencesAuth] })
	@OAuthScopes("read:post")
	@Get("posts")
	posts(@CurrentUser("id") userId: string) {
		return { userId };
	}
}

/**
 * What an app's filter sees: Nest's own 401/403, with this package's error
 * as its `cause`.
 */
@Catch()
class OAuthErrorFilter implements ExceptionFilter {
	catch(exception: HttpException, host: ArgumentsHost) {
		const cause = exception.cause;
		const kind =
			cause instanceof OAuthInsufficientScopeError
				? { kind: "insufficient-scope", scopes: cause.scopes }
				: cause instanceof OAuthAccessTokenNotAcceptedError
					? { kind: "not-accepted" }
					: cause instanceof OAuthAccessTokenError
						? { kind: "bad-token", code: cause.code }
						: { kind: "other" };
		host
			.switchToHttp()
			.getResponse()
			.status(exception.getStatus())
			.send({
				...kind,
				authenticationError: cause instanceof AuthenticationError,
			});
	}
}

@Controller("api")
class ApiController {
	@UseFilters(new OAuthErrorFilter())
	@OAuthScopes("read:post")
	@Get("filtered/posts")
	filteredPosts() {
		return { ok: true };
	}

	@UseFilters(new OAuthErrorFilter())
	@Get("filtered/account")
	filteredAccount() {
		return { ok: true };
	}

	@OAuthScopes("read:post")
	@Get("posts")
	posts(
		@CurrentUser("id") userId: string,
		@CurrentSession() session: BetterAuthOAuthAccessToken | { token: string },
	) {
		return { userId, session };
	}

	@OAuthScopes()
	@Get("any-token")
	anyToken(@CurrentUser("id") userId: string) {
		return { userId };
	}

	@Authenticate({ providers: [MachineOAuthAuth] })
	@OAuthScopes("read:post")
	@Get("machine/posts")
	machinePosts(@CurrentUser() caller: ClientPrincipal | AppUser) {
		return { caller };
	}

	@Authenticate({ providers: [BothAudiencesAuth] })
	@OAuthScopes("read:post")
	@Get("both/posts")
	bothPosts(@CurrentUser("id") userId: string) {
		return { userId };
	}

	/** No `@OAuthScopes()`: a first-party route. */
	@Get("account")
	account(@CurrentUser("id") userId: string) {
		return { userId };
	}
}

const createAuth = () =>
	createTestAuth({
		baseURL: ORIGIN,
		disabledPaths: ["/token"],
		plugins: [
			admin(),
			// The audience of jwt()'s own JWTs is this API too: they share the
			// keys, the issuer and the audience with the access tokens.
			jwt({
				disableSettingJwtHeader: true,
				jwt: { issuer: ISSUER, audience: API },
			}),
			oauthProvider({
				loginPage: "/sign-in",
				consentPage: "/consent",
				scopes: ["openid", "profile", "email", "offline_access", "read:post"],
				resources: [API, MCP],
				clientRegistrationDefaultResources: [API, MCP],
				// Lets the tests set client_credentials_scopes.
				clientPrivileges: () => true,
			}),
		],
	});

describe("oauthProvider() through BetterAuthOAuthProviderModule", () => {
	let app: Awaited<ReturnType<typeof createTestApp>>["app"];
	let auth: ReturnType<typeof createAuth>;
	let server: ReturnType<typeof app.getHttpServer>;

	beforeAll(async () => {
		auth = createAuth();
		({ app } = await createTestApp({
			auth,
			imports: [BetterAuthOAuthProviderModule],
			providers: [
				oauthAuth({
					audience: API,
					resourceMetadata: { scopes_supported: ["read:post"] },
				}),
				MachineOAuthAuth,
				BothAudiencesAuth,
			],
			controllers: [ApiController, McpController],
		}));
		server = app.getHttpServer();
	});

	afterAll(async () => {
		await app.close();
	});

	const { signIn, createClient, authorize } = oauthFlows({
		server: () => server,
		auth: () => auth,
		issuer: ISSUER,
	});

	describe("discovery", () => {
		it("serves RFC 8414's metadata at the root, outside the base path", async () => {
			const response = await request(server).get(
				"/.well-known/oauth-authorization-server/api/auth",
			);
			expect(response.status).toBe(200);
			expect(response.body.issuer).toBe(ISSUER);
			expect(response.body.token_endpoint).toBe(`${ISSUER}/oauth2/token`);
		});

		it("serves the issuer's own documents", async () => {
			for (const path of [
				"/api/auth/.well-known/openid-configuration",
				"/api/auth/.well-known/oauth-authorization-server",
			]) {
				const response = await request(server).get(path);
				expect(response.status).toBe(200);
				expect(response.body.issuer).toBe(ISSUER);
			}
		});

		it("serves this API's protected resource metadata (RFC 9728), to any origin", async () => {
			const response = await request(server)
				.get("/.well-known/oauth-protected-resource/api")
				.set("Origin", "https://elsewhere.test");
			expect(response.status).toBe(200);
			expect(response.headers["access-control-allow-origin"]).toBe("*");
			expect(response.body).toMatchObject({
				resource: API,
				authorization_servers: [ISSUER],
				bearer_methods_supported: ["header"],
				scopes_supported: ["read:post"],
			});

			const preflight = await request(server)
				.options("/.well-known/oauth-protected-resource/api")
				.set("Origin", "https://elsewhere.test")
				.set("Access-Control-Request-Method", "GET")
				.set("Access-Control-Request-Headers", "mcp-protocol-version");
			expect(preflight.status).toBe(204);
			expect(preflight.headers["access-control-allow-origin"]).toBe("*");
		});

		it("leaves other well-known paths to the app", async () => {
			const response = await request(server).get(
				"/.well-known/oauth-authorization-server/elsewhere",
			);
			expect(response.status).toBe(404);
			expect(response.body.statusCode).toBe(404); // Nest's, not Better Auth's
		});
	});

	describe("access tokens on Nest routes", () => {
		it("authenticates the user who granted the token, on a route asking for its scopes", async () => {
			const user = await signIn();
			const client = await createClient(user.cookie);
			const { access_token } = await authorize(user, client, {
				scope: "openid read:post",
				resource: API,
			});

			const response = await request(server)
				.get("/api/posts")
				.set("Authorization", `Bearer ${access_token}`);
			expect(response.status).toBe(200);
			expect(response.body.userId).toBe(user.userId);
			expect(response.body.session).toMatchObject({
				sub: user.userId,
				azp: client.client_id,
				scopes: ["openid", "read:post"],
			});

			const any = await request(server)
				.get("/api/any-token")
				.set("Authorization", `Bearer ${access_token}`);
			expect(any.status).toBe(200);
		});

		it("refuses them on routes without @OAuthScopes(), even when jwt() would accept them", async () => {
			const user = await signIn();
			const client = await createClient(user.cookie);
			const { access_token } = await authorize(user, client, {
				scope: "openid read:post",
				resource: API,
			});

			const response = await request(server)
				.get("/api/account")
				.set("Authorization", `Bearer ${access_token}`);
			expect(response.status).toBe(403);
			expect(response.body.errorCode).toBe("access_token_not_accepted");
		});

		it("answers a missing scope with RFC 6750's insufficient_scope challenge", async () => {
			const user = await signIn();
			const client = await createClient(user.cookie);
			const { access_token } = await authorize(user, client, {
				scope: "openid profile",
				resource: API,
			});

			const response = await request(server)
				.get("/api/posts")
				.set("Authorization", `Bearer ${access_token}`);
			expect(response.status).toBe(403);
			expect(response.body.errorCode).toBe("insufficient_scope");
			expect(response.body.details).toEqual({ scope: "read:post" });
			const challenge = response.headers["www-authenticate"];
			expect(challenge).toContain('error="insufficient_scope"');
			expect(challenge).toContain('scope="read:post"');
			expect(challenge).toContain(`resource_metadata="${METADATA}"`);
		});

		it("points clients without credentials to the resource metadata", async () => {
			const response = await request(server).get("/api/posts");
			expect(response.status).toBe(401);
			expect(response.headers["www-authenticate"]).toContain(
				`Bearer resource_metadata="${METADATA}"`,
			);
		});

		it("refuses a forged token with invalid_token", async () => {
			const user = await signIn();
			const client = await createClient(user.cookie);
			const { access_token } = await authorize(user, client, {
				scope: "openid read:post",
				resource: API,
			});
			const [header, payload] = access_token.split(".");
			const forged = `${header}.${payload}.${randomBytes(64).toString("base64url")}`;

			const response = await request(server)
				.get("/api/posts")
				.set("Authorization", `Bearer ${forged}`);
			expect(response.status).toBe(401);
			expect(response.headers["www-authenticate"]).toContain(
				'error="invalid_token"',
			);
		});

		it("never takes an ID token for an access token", async () => {
			const user = await signIn();
			const client = await createClient(user.cookie);
			const { id_token } = await authorize(user, client, {
				scope: "openid read:post",
				resource: API,
			});
			expect(id_token).toBeTruthy();

			for (const path of ["/api/posts", "/api/account"]) {
				const response = await request(server)
					.get(path)
					.set("Authorization", `Bearer ${id_token}`);
				expect(response.status).toBe(401);
			}
		});

		it("leaves tokens requested without this API as resource unauthenticated", async () => {
			const user = await signIn();
			const client = await createClient(user.cookie);
			// Opaque: meant for the userinfo endpoint only.
			const { access_token } = await authorize(user, client, {
				scope: "openid read:post",
			});

			const response = await request(server)
				.get("/api/posts")
				.set("Authorization", `Bearer ${access_token}`);
			expect(response.status).toBe(401);
		});

		it("refuses a token once the session it was granted from ended", async () => {
			const user = await signIn();
			const client = await createClient(user.cookie);
			const { access_token } = await authorize(user, client, {
				scope: "openid read:post",
				resource: API,
			});
			const before = await request(server)
				.get("/api/posts")
				.set("Authorization", `Bearer ${access_token}`);
			expect(before.status).toBe(200);
			expect(before.body.session.sid).toBeTruthy();

			await request(server)
				.post("/api/auth/sign-out")
				.set("Cookie", user.cookie)
				.set("Origin", ORIGIN)
				.expect(200);

			const after = await request(server)
				.get("/api/posts")
				.set("Authorization", `Bearer ${access_token}`);
			expect(after.status).toBe(401);
			expect(after.headers["www-authenticate"]).toContain(
				'error="invalid_token"',
			);
		});

		/** A `client_credentials` token for a new client, and the client. */
		const clientCredentials = async () => {
			const user = await signIn();
			const client = await createClient(user.cookie, {
				grant_types: ["client_credentials"],
				response_types: [],
				scope: "read:post",
				client_credentials_scopes: ["read:post"],
			});
			const token = await request(server)
				.post("/api/auth/oauth2/token")
				.type("form")
				.auth(client.client_id, client.client_secret)
				.send({
					grant_type: "client_credentials",
					scope: "read:post",
					resource: API,
				});
			expect(token.status).toBe(200);
			return { client, accessToken: token.body.access_token as string };
		};

		it("refuses client_credentials tokens, which have no user", async () => {
			const { accessToken } = await clientCredentials();

			const response = await request(server)
				.get("/api/posts")
				.set("Authorization", `Bearer ${accessToken}`);
			expect(response.status).toBe(403);
			expect(response.body.errorCode).toBe("user_required");
		});

		describe("a provider with several audiences", () => {
			const tokenFor = async (resource: string) => {
				const user = await signIn();
				const client = await createClient(user.cookie);
				const { access_token } = await authorize(user, client, {
					scope: "openid read:post",
					resource,
				});
				return { user, accessToken: access_token };
			};

			it("accepts a token for any of them, wherever it is asked", async () => {
				for (const resource of [API, MCP]) {
					const { user, accessToken } = await tokenFor(resource);
					for (const path of ["/mcp/posts", "/api/both/posts"]) {
						const response = await request(server)
							.get(path)
							.set("Authorization", `Bearer ${accessToken}`);
						expect(response.status).toBe(200);
						expect(response.body.userId).toBe(user.userId);
					}
				}
			});

			it("leaves a single-audience provider refusing the others", async () => {
				const { accessToken } = await tokenFor(MCP);
				const response = await request(server)
					.get("/api/posts")
					.set("Authorization", `Bearer ${accessToken}`);
				expect(response.status).toBe(401);
			});

			it("points its challenges to the audience the request's path is under", async () => {
				const metadataOf = (resource: string) =>
					resource.replace(
						ORIGIN,
						`${ORIGIN}/.well-known/oauth-protected-resource`,
					);
				const firstMetadata = (header: string | undefined) =>
					/resource_metadata="([^"]*)"/.exec(header ?? "")?.[1];

				for (const [path, resource] of [
					["/mcp/posts", MCP],
					["/api/both/posts", API],
				] as const) {
					const none = await request(server).get(path);
					expect(none.status).toBe(401);
					expect(none.headers["www-authenticate"]).toBe(
						`Bearer resource_metadata="${metadataOf(resource)}"`,
					);

					// The resource client's own refusal lists each audience, this one first.
					const { accessToken } = await tokenFor(API);
					const [header, payload] = accessToken.split(".");
					const forged = await request(server)
						.get(path)
						.set(
							"Authorization",
							`Bearer ${header}.${payload}.${randomBytes(64).toString("base64url")}`,
						);
					expect(forged.status).toBe(401);
					expect(firstMetadata(forged.headers["www-authenticate"])).toBe(
						metadataOf(resource),
					);
				}
			});
		});

		describe("a provider whose validate() admits clients", () => {
			it("authenticates a client_credentials token as the principal it returns", async () => {
				const { client, accessToken } = await clientCredentials();

				const response = await request(server)
					.get("/api/machine/posts")
					.set("Authorization", `Bearer ${accessToken}`);
				expect(response.status).toBe(200);
				expect(response.body.caller).toEqual({
					kind: "client",
					clientId: client.client_id,
				});
			});

			it("authenticates a user's token as the principal it builds for them", async () => {
				const user = await signIn();
				const client = await createClient(user.cookie);
				const { access_token } = await authorize(user, client, {
					scope: "openid read:post",
					resource: API,
				});

				const response = await request(server)
					.get("/api/machine/posts")
					.set("Authorization", `Bearer ${access_token}`);
				expect(response.status).toBe(200);
				expect(response.body.caller).toEqual({
					kind: "user",
					id: user.userId,
				});
			});

			it("still refuses a banned user's token, though its principal has no ban field", async () => {
				const user = await signIn();
				const client = await createClient(user.cookie);
				const { access_token } = await authorize(user, client, {
					scope: "openid read:post",
					resource: API,
				});
				const ctx = await auth.$context;
				await ctx.internalAdapter.updateUser(user.userId, { banned: true });

				for (const path of ["/api/machine/posts", "/api/posts"]) {
					const response = await request(server)
						.get(path)
						.set("Authorization", `Bearer ${access_token}`);
					expect(response.status).toBe(403);
					expect(response.body.errorCode).toBe("banned_user");
				}
			});
		});

		it("verifies DPoP-bound tokens against the proof for this request", async () => {
			const user = await signIn();
			const client = await createClient(user.cookie);
			const key = dpopKey();
			const { access_token, token_type } = await authorize(user, client, {
				scope: "openid read:post",
				resource: API,
				dpop: key,
			});
			expect(token_type).toBe("DPoP");

			const call = (proof?: string, scheme = "DPoP") => {
				const call = request(server)
					.get("/api/posts")
					.set("Host", "localhost:3000")
					.set("Authorization", `${scheme} ${access_token}`);
				return proof ? call.set("DPoP", proof) : call;
			};

			const ok = await call(key.proof("GET", `${API}/posts`, access_token));
			expect(ok.status).toBe(200);
			expect(ok.body.userId).toBe(user.userId);

			// A proof for another URL, none at all, or the token as a Bearer one.
			expect(
				(await call(key.proof("GET", `${API}/other`, access_token))).status,
			).toBe(401);
			expect((await call()).status).toBe(401);
			expect(
				(await call(key.proof("GET", `${API}/posts`, access_token), "Bearer"))
					.status,
			).toBe(401);
		});

		it("hands its errors to the app's exception filters, as the cause", async () => {
			const user = await signIn();
			const client = await createClient(user.cookie);
			const { access_token } = await authorize(user, client, {
				scope: "openid profile",
				resource: API,
			});
			const call = (path: string, token = access_token) =>
				request(server).get(path).set("Authorization", `Bearer ${token}`);

			const scope = await call("/api/filtered/posts");
			expect(scope.status).toBe(403);
			expect(scope.body).toEqual({
				kind: "insufficient-scope",
				scopes: ["read:post"],
				authenticationError: true,
			});

			const notAccepted = await call("/api/filtered/account");
			expect(notAccepted.status).toBe(403);
			expect(notAccepted.body.kind).toBe("not-accepted");

			const [header, payload] = access_token.split(".");
			const forged = await call(
				"/api/filtered/posts",
				`${header}.${payload}.${randomBytes(64).toString("base64url")}`,
			);
			expect(forged.status).toBe(401);
			expect(forged.body).toEqual({
				kind: "bad-token",
				code: "invalid_token",
				authenticationError: true,
			});
		});

		it("keeps the session cookie working on routes with @OAuthScopes()", async () => {
			const user = await signIn();
			const response = await request(server)
				.get("/api/posts")
				.set("Cookie", user.cookie);
			expect(response.status).toBe(200);
			expect(response.body.userId).toBe(user.userId);
		});
	});
});

describe("oauthProvider() without a BetterAuthOAuthProvider (an authorization server only)", () => {
	it("serves discovery, and doesn't take access tokens for jwt() JWTs", async () => {
		const auth = createAuth();
		const { app } = await createTestApp({ auth, controllers: [ApiController] });
		const server = app.getHttpServer();
		try {
			const discovery = await request(server).get(
				"/.well-known/oauth-authorization-server/api/auth",
			);
			expect(discovery.status).toBe(200);
			expect(
				(await request(server).get("/.well-known/oauth-protected-resource/api"))
					.status,
			).toBe(404);

			const signUp = await request(server)
				.post("/api/auth/sign-up/email")
				.send({ email: uniqueEmail(), password: "password1234", name: "User" });
			const cookie = (signUp.headers["set-cookie"] as unknown as string[])
				.map((value) => value.split(";")[0])
				.join("; ");
			const client = (await (
				auth.api as unknown as OAuthApi
			).adminCreateOAuthClient({
				headers: new Headers({ cookie }),
				body: {
					redirect_uris: [REDIRECT],
					skip_consent: true,
					scope: "openid read:post",
				},
			})) as OAuthClient;
			const verifier = randomBytes(32).toString("base64url");
			const redirect = await request(server)
				.get(
					`/api/auth/oauth2/authorize?${new URLSearchParams({
						response_type: "code",
						client_id: client.client_id,
						redirect_uri: REDIRECT,
						scope: "openid read:post",
						state: "state",
						code_challenge: createHash("sha256")
							.update(verifier)
							.digest("base64url"),
						code_challenge_method: "S256",
						resource: API,
					})}`,
				)
				.set("Cookie", cookie);
			const token = await request(server)
				.post("/api/auth/oauth2/token")
				.type("form")
				.auth(client.client_id, client.client_secret)
				.send({
					grant_type: "authorization_code",
					code: new URL(redirect.headers.location as string).searchParams.get(
						"code",
					),
					redirect_uri: REDIRECT,
					code_verifier: verifier,
					resource: API,
				});
			expect(token.status).toBe(200);

			// jwt() checks the same keys, issuer and audience: only the token's
			// type keeps it from passing for the user's whole session.
			const response = await request(server)
				.get("/api/account")
				.set("Authorization", `Bearer ${token.body.access_token}`);
			expect(response.status).toBe(401);
		} finally {
			await app.close();
		}
	});
});

describe("BetterAuthOAuthProvider settings", () => {
	it("fails at startup without the oauthProvider() plugin", async () => {
		await expect(
			createTestApp({
				auth: createTestAuth({ baseURL: ORIGIN, plugins: [jwt()] }),
				imports: [BetterAuthOAuthProviderModule],
				providers: [oauthAuth({ audience: API })],
				controllers: [],
			}),
		).rejects.toThrow(/oauthProvider\(\)/);
	});

	it("fails at startup without BetterAuthOAuthProviderModule", async () => {
		await expect(
			createTestApp({
				auth: createAuth(),
				providers: [oauthAuth({ audience: API })],
				controllers: [],
			}),
		).rejects.toThrow(/needs BetterAuthOAuthProviderModule/);
	});

	it("fails at startup with two providers serving one resource's metadata", async () => {
		await expect(
			createTestApp({
				auth: createAuth(),
				imports: [BetterAuthOAuthProviderModule],
				providers: [
					oauthAuth({ audience: API }),
					oauthAuth({ audience: API }, 4),
				],
				controllers: [],
			}),
		).rejects.toThrow(/both serve the resource metadata/);
	});

	it("serves one resource metadata document per audience", async () => {
		const { app } = await createTestApp({
			auth: createAuth(),
			imports: [BetterAuthOAuthProviderModule],
			providers: [oauthAuth({ audience: [API, MCP] })],
			controllers: [],
		});
		try {
			for (const [path, resource] of [
				["/.well-known/oauth-protected-resource/api", API],
				["/.well-known/oauth-protected-resource/mcp", MCP],
			]) {
				const response = await request(app.getHttpServer())
					.get(path)
					.expect(200);
				expect(response.body.resource).toBe(resource);
			}
		} finally {
			await app.close();
		}
	});

	it.each([
		["no audience", [], /non-empty array/],
		["one that isn't an http(s) URL", [API, "urn:mcp"], /urn:mcp/],
		["one listed twice", [API, API], /twice/],
		[
			"two whose metadata would share a path",
			[API, "https://other.example/api"],
			/same path/,
		],
	])("fails at startup on audiences with %s", async (_, audience, message) => {
		await expect(
			createTestApp({
				auth: createAuth(),
				imports: [BetterAuthOAuthProviderModule],
				providers: [oauthAuth({ audience })],
				controllers: [],
			}),
		).rejects.toThrow(message);
	});

	it("fails at startup on an audience that isn't an http(s) URL", async () => {
		await expect(
			createTestApp({
				auth: createAuth(),
				imports: [BetterAuthOAuthProviderModule],
				providers: [oauthAuth({ audience: "urn:api" })],
				controllers: [],
			}),
		).rejects.toThrow(/audience/);
	});

	it("fails at startup on resource metadata the plugin refuses", async () => {
		await expect(
			createTestApp({
				auth: createAuth(),
				imports: [BetterAuthOAuthProviderModule],
				providers: [
					oauthAuth({
						audience: API,
						resourceMetadata: { scopes_supported: ["unknown"] },
					}),
				],
				controllers: [],
			}),
		).rejects.toThrow(/unknown/i);
	});
});
