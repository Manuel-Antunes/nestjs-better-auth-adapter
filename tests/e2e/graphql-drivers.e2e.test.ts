import { oauthProvider } from "@better-auth/oauth-provider";
import {
	YogaFederationDriver,
	type YogaFederationDriverConfig,
} from "@graphql-yoga/nestjs-federation";
import { YogaDriver, type YogaDriverConfig } from "@graphql-yoga/nestjs";
import {
	ApolloDriver,
	type ApolloDriverConfig,
	ApolloFederationDriver,
	type ApolloFederationDriverConfig,
} from "@nestjs/apollo";
import {
	type DynamicModule,
	type INestApplication,
	Inject,
	Injectable,
} from "@nestjs/common";
import {
	Authenticate,
	AuthenticationRegistry,
	CurrentUser,
	Public,
} from "@nestjs/authentication";
import { Can, Policy } from "@nestjs/authorization";
import {
	Directive,
	Field,
	GraphQLModule,
	ID,
	ObjectType,
	Query,
	ResolveReference,
	Resolver,
	Subscription,
} from "@nestjs/graphql";
import { jwt } from "better-auth/plugins/jwt";
import request from "supertest";
import type { BetterAuthUser } from "../../src/index.ts";
import {
	BetterAuthOAuthProvider,
	BetterAuthOAuthProviderModule,
	OAuthScopes,
} from "../../src/oauth-provider/index.ts";
import {
	apolloContext,
	createTestApp,
	createTestAuth,
	signUp,
} from "../shared/app.ts";
import { oauthFlows } from "../shared/oauth.ts";

const ORIGIN = "http://localhost:3000";
const ISSUER = `${ORIGIN}/api/auth`;
/** The GraphQL API, as a resource server. */
const API = `${ORIGIN}/graphql`;

/** Signed-in callers only: what `@Can()` sees is the authenticated user. */
@Policy()
class CallerPolicy {
	async read(user: BetterAuthUser | null) {
		return user !== null;
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

/**
 * Optional authentication, so a guest reaches the policy: the policy, not
 * the authentication guard, tells whether it got the caller.
 */
@Resolver()
class CallerResolver {
	@Public()
	@Can.Anyone()
	@Query(() => String)
	hello() {
		return "ok";
	}

	@Authenticate({ optional: true })
	@OAuthScopes("read:post")
	@Can(CallerPolicy, "read")
	@Query(() => String)
	me(@CurrentUser("id") id: string) {
		return id;
	}

	@Authenticate({ optional: true })
	@OAuthScopes("read:post")
	@Can(CallerPolicy, "read")
	@Subscription(() => String, { resolve: (id: string) => id })
	async *callerIds(@CurrentUser("id") id: string) {
		yield id;
		yield id;
	}
}

@ObjectType()
@Directive('@key(fields: "id")')
class Article {
	@Field(() => ID)
	id!: string;
}

/** A subgraph's entity, resolved for the router behind `@Can()`. */
@Resolver(() => Article)
class ArticleResolver {
	@Public()
	@Can.Anyone()
	@Query(() => Article)
	article(): Article {
		return { id: "1" };
	}

	@Authenticate({ optional: true })
	@Can(CallerPolicy, "read")
	@ResolveReference()
	resolveReference(reference: { id: string }): Article {
		return { id: reference.id };
	}
}

const drivers: [string, () => DynamicModule][] = [
	[
		"ApolloDriver",
		() =>
			GraphQLModule.forRoot<ApolloDriverConfig>({
				driver: ApolloDriver,
				autoSchemaFile: true,
				path: "/graphql",
				context: apolloContext,
			}),
	],
	[
		"YogaDriver",
		() =>
			GraphQLModule.forRoot<YogaDriverConfig>({
				driver: YogaDriver,
				autoSchemaFile: true,
				path: "/graphql",
				logging: false,
			}),
	],
];

const federationDrivers: [string, () => DynamicModule][] = [
	[
		"ApolloFederationDriver",
		() =>
			GraphQLModule.forRoot<ApolloFederationDriverConfig>({
				driver: ApolloFederationDriver,
				autoSchemaFile: { federation: 2 },
				path: "/graphql",
				// Guards (authentication, @Can()) on reference resolvers.
				fieldResolverEnhancers: ["guards"],
				context: apolloContext,
			}),
	],
	[
		"YogaFederationDriver",
		() =>
			GraphQLModule.forRoot<YogaFederationDriverConfig>({
				driver: YogaFederationDriver,
				autoSchemaFile: { federation: 2 },
				path: "/graphql",
				// Guards (authentication, @Can()) on reference resolvers.
				fieldResolverEnhancers: ["guards"],
				logging: false,
			}),
	],
];

const createAuth = () =>
	createTestAuth({
		baseURL: ORIGIN,
		disabledPaths: ["/token"],
		// Refreshed on every request, and cached in a cookie: each response
		// carries the cookies getSession() sets.
		session: { updateAge: 0, cookieCache: { enabled: true } },
		plugins: [
			jwt({
				disableSettingJwtHeader: true,
				jwt: { issuer: ISSUER, audience: API },
			}),
			oauthProvider({
				loginPage: "/sign-in",
				consentPage: "/consent",
				scopes: ["openid", "profile", "read:post"],
				resources: [API],
				clientRegistrationDefaultResources: [API],
			}),
		],
	});

/** The session cookie of a new user, signed up through Better Auth's route. */
async function cookieOf(server: unknown) {
	const response = await request(server as never)
		.post("/api/auth/sign-up/email")
		.send({
			email: `${crypto.randomUUID()}@example.com`,
			password: "password1234",
			name: "User",
		})
		.expect(200);
	const cookie = (response.headers["set-cookie"] as unknown as string[])
		.map((value) => value.split(";")[0])
		.join("; ");
	return { cookie, userId: response.body.user.id as string };
}

const cookiesOf = (response: request.Response) =>
	([] as string[]).concat(response.headers["set-cookie"] ?? []);

describe.each(drivers)("GraphQL through %s", (driver, graphqlModule) => {
	let app: INestApplication;
	let auth: ReturnType<typeof createAuth>;
	let server: ReturnType<INestApplication["getHttpServer"]>;
	const { signIn, createClient, authorize } = oauthFlows({
		server: () => server,
		auth: () => auth,
		issuer: ISSUER,
	});

	beforeAll(async () => {
		auth = createAuth();
		({ app } = await createTestApp({
			auth,
			authorization: true,
			graphqlModule: graphqlModule(),
			imports: [BetterAuthOAuthProviderModule],
			providers: [CallerResolver, CallerPolicy, OAuthAuth],
			controllers: [],
		}));
		server = app.getHttpServer();
	});

	afterAll(async () => {
		await app.close();
	});

	const query = (source: string, headers: Record<string, string> = {}) =>
		request(server).post("/graphql").set(headers).send({ query: source });

	it("resolves a public query", async () => {
		const response = await query("{ hello }").expect(200);
		expect(response.body.data).toEqual({ hello: "ok" });
	});

	it("hands the policy a guest without credentials, and refuses it", async () => {
		const response = await query("{ me }");
		expect(response.body.data?.me ?? null).toBeNull();
		expect(response.body.errors?.[0]?.message).toMatch(
			/unauthorized|forbidden/i,
		);
	});

	it("authenticates a session token, and hands the policy its user", async () => {
		const { token, user } = await signUp(auth);
		const response = await query("{ me }", {
			Authorization: `Bearer ${token}`,
		}).expect(200);
		expect(response.body.data).toEqual({ me: user.id });
	});

	it("authenticates the session cookie", async () => {
		const { cookie, userId } = await cookieOf(server);
		const response = await query("{ me }", { Cookie: cookie }).expect(200);
		expect(response.body.data).toEqual({ me: userId });
	});

	it("sends the cookies getSession() refreshes", async () => {
		const { token } = await signUp(auth);
		const response = await query("{ me }", {
			Authorization: `Bearer ${token}`,
		}).expect(200);

		const cookies = cookiesOf(response);
		expect(cookies.some((c) => c.includes("session_token="))).toBe(true);
		expect(cookies.some((c) => c.includes("session_data="))).toBe(true);
	});

	it("authenticates an OAuth access token", async () => {
		const user = await signIn();
		const client = await createClient(user.cookie);
		const { access_token } = await authorize(user, client, {
			scope: "openid read:post",
			resource: API,
		});
		const response = await query("{ me }", {
			Authorization: `Bearer ${access_token}`,
		}).expect(200);
		expect(response.body.data).toEqual({ me: user.userId });
	});

	if (driver === "YogaDriver") {
		/** A subscription over SSE, on the GraphQL endpoint: its events' payloads. */
		const subscribe = async (
			source: string,
			headers: Record<string, string>,
		) => {
			const response = await request(server)
				.post("/graphql")
				.set({ Accept: "text/event-stream", ...headers })
				.send({ query: source })
				.buffer(true)
				.parse((res, done) => {
					let text = "";
					res.setEncoding("utf8");
					res.on("data", (chunk: string) => {
						text += chunk;
					});
					res.on("end", () => done(null, text));
				});
			expect(response.headers["content-type"]).toContain("text/event-stream");
			return {
				status: response.status,
				events: (response.body as string)
					.split("\n")
					.filter((line) => line.startsWith("data: ") && line.length > 6)
					.map((line) => JSON.parse(line.slice(6))),
			};
		};

		it("authenticates an SSE subscription by its session cookie", async () => {
			const { cookie, userId } = await cookieOf(server);
			const { status, events } = await subscribe("subscription { callerIds }", {
				Cookie: cookie,
			});
			expect(status).toBe(200);
			expect(events).toEqual([
				{ data: { callerIds: userId } },
				{ data: { callerIds: userId } },
			]);
		});

		it("authenticates an SSE subscription by an OAuth access token", async () => {
			const user = await signIn();
			const client = await createClient(user.cookie);
			const { access_token } = await authorize(user, client, {
				scope: "openid read:post",
				resource: API,
			});
			const { status, events } = await subscribe("subscription { callerIds }", {
				Authorization: `Bearer ${access_token}`,
			});
			expect(status).toBe(200);
			expect(events).toEqual([
				{ data: { callerIds: user.userId } },
				{ data: { callerIds: user.userId } },
			]);
		});

		it("refuses an SSE subscription without credentials", async () => {
			// A subscription refused before its first event has errors and no
			// data: Yoga answers it with a 500, unless the error carries
			// extensions.http.status (see the README).
			const { events } = await subscribe("subscription { callerIds }", {});
			expect(events).toHaveLength(1);
			expect(events[0].errors?.[0]?.message).toMatch(/unauthorized/i);
		});
	}
});

describe.each(federationDrivers)(
	"a federation subgraph through %s",
	(_, graphqlModule) => {
		let app: INestApplication;
		let auth: ReturnType<typeof createTestAuth>;

		beforeAll(async () => {
			auth = createTestAuth();
			({ app } = await createTestApp({
				auth,
				authorization: true,
				graphqlModule: graphqlModule(),
				providers: [ArticleResolver, CallerPolicy],
				controllers: [],
			}));
		});

		afterAll(async () => {
			await app.close();
		});

		/** What a router sends a subgraph to resolve an entity: no `args` reach the reference resolver. */
		const entities = (headers: Record<string, string> = {}) =>
			request(app.getHttpServer())
				.post("/graphql")
				.set(headers)
				.send({
					query: `query ($representations: [_Any!]!) {
					_entities(representations: $representations) { ... on Article { id } }
				}`,
					variables: { representations: [{ __typename: "Article", id: "7" }] },
				})
				.expect(200);

		it("hands the reference resolver's policy the caller", async () => {
			const { token } = await signUp(auth);
			const response = await entities({ Authorization: `Bearer ${token}` });
			expect(response.body.errors).toBeUndefined();
			expect(response.body.data).toEqual({ _entities: [{ id: "7" }] });
		});

		it("hands it a guest without credentials, and refuses it", async () => {
			const response = await entities();
			expect(response.body.data?._entities?.[0] ?? null).toBeNull();
			expect(response.body.errors?.[0]?.message).toMatch(
				/unauthorized|forbidden/i,
			);
		});
	},
);
