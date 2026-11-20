import "reflect-metadata";
import {
	Controller,
	Get,
	Module,
	Post,
	type DynamicModule,
	type INestApplication,
	type Provider,
	type Type,
	type WebSocketAdapter,
} from "@nestjs/common";
import { Test } from "@nestjs/testing";
import { ApolloDriver, type ApolloDriverConfig } from "@nestjs/apollo";
import { GraphQLModule, Query, Resolver } from "@nestjs/graphql";
import { SubscribeMessage, WebSocketGateway } from "@nestjs/websockets";
import {
	ApiKeyProvider,
	Authenticate,
	AuthenticationContext,
	AuthenticationModule,
	type AuthenticationModuleOptions,
	CurrentSession,
	CurrentUser,
	Public,
} from "@nestjs/authentication";
import { AuthorizationModule } from "@nestjs/authorization";
import { betterAuth } from "better-auth";
import { bearer } from "better-auth/plugins/bearer";
import type { Request, Response } from "express";
import {
	BetterAuthModule,
	type BetterAuthModuleOptions,
	BetterAuthSessionProvider,
} from "../../src/index.ts";
import { nestjs } from "../../src/plugin/index.ts";
import { defaultAuthProviders } from "./auth-providers.ts";
import { createTestHttpAdapter, initTestApplication } from "./http-adapter.ts";

export type BetterAuthOptions = Parameters<typeof betterAuth>[0];
export type TestAuth = ReturnType<typeof createTestAuth>;

/**
 * Cheap stand-in for scrypt: most suites create dozens of users and don't
 * test passwords, and hashing them for real makes the suites CPU bound.
 * Suites about hashing pass their own `emailAndPassword`.
 */
const fastPassword = {
	hash: async (password: string) => `plain:${password}`,
	verify: async ({ hash, password }: { hash: string; password: string }) =>
		hash === `plain:${password}`,
};

/**
 * A Better Auth instance with the `bearer()` and `nestjs()` plugins, plus the
 * `plugins` of `options` (which may bring their own `nestjs()`).
 */
export function createTestAuth(options?: Partial<BetterAuthOptions>) {
	const plugins = options?.plugins ?? [];
	return betterAuth({
		basePath: "/api/auth",
		emailAndPassword: { enabled: true, password: fastPassword },
		logger: { disabled: true },
		...options,
		plugins: [
			bearer(),
			...(plugins.some((plugin) => plugin.id === "nestjs") ? [] : [nestjs()]),
			...plugins,
		],
	});
}

/** Routes exercising `@nestjs/authentication`'s decorators. */
@Controller("test")
export class TestController {
	constructor(private readonly context: AuthenticationContext) {}

	@Get("protected")
	protected(
		@CurrentUser() user: { id: string },
		@CurrentSession() session: Record<string, unknown>,
	) {
		return { user, session };
	}

	@Public()
	@Get("public")
	public(@CurrentUser() user: unknown) {
		return { ok: true, user };
	}

	@Authenticate({ optional: true })
	@Get("optional")
	optional(@CurrentUser() user: { id: string } | null) {
		return { authenticated: !!user, userId: user?.id ?? null };
	}

	@Authenticate({ verifiedEmail: true })
	@Get("verified")
	verified(@CurrentUser("email") email: string) {
		return { email };
	}

	@Authenticate({ mfa: true })
	@Get("mfa")
	mfa() {
		return { ok: true };
	}

	@Authenticate({ providers: [BetterAuthSessionProvider] })
	@Get("session-only")
	sessionOnly(@CurrentUser("id") id: string) {
		return { id };
	}

	@Authenticate({ providers: [ApiKeyProvider] })
	@Get("api-key-only")
	apiKeyOnly(@CurrentUser("id") id: string) {
		return { id };
	}

	@Post("write")
	write(@CurrentUser("id") id: string) {
		return { id };
	}

	@Get("context")
	contextUser() {
		return { id: this.context.requireUser().id };
	}
}

/** GraphQL queries for the transport tests. */
@Resolver()
export class TestResolver {
	@Public()
	@Query(() => String)
	publicHello(): string {
		return "ok";
	}

	@Authenticate({ optional: true })
	@Query(() => Boolean)
	optionalAuthenticated(@CurrentUser() user: unknown): boolean {
		return !!user;
	}

	@Query(() => String)
	protectedUserId(@CurrentUser("id") id: string): string {
		return id;
	}
}

/** WebSocket events for the transport tests. */
@WebSocketGateway({ path: "/ws", namespace: "test", cors: { origin: "*" } })
export class TestGateway {
	@Public()
	@SubscribeMessage("anonymous")
	anonymous() {
		return { event: "anonymous", data: "hello" };
	}

	@Authenticate({ optional: true })
	@SubscribeMessage("optional")
	optional(@CurrentUser() user: { name: string } | null) {
		return { event: "optional", data: user?.name ?? null };
	}

	@SubscribeMessage("protected")
	protectedMessage(@CurrentUser("name") name: string) {
		return { event: "protected", data: name };
	}
}

export interface TestAppOptions {
	auth: TestAuth;
	/** Options of `BetterAuthModule.forRoot()` besides `auth`. */
	module?: Omit<BetterAuthModuleOptions, "auth">;
	/** Replaces `BetterAuthModule.forRoot({ auth, ...module })`. */
	betterAuthModule?: DynamicModule;
	controllers?: Type<unknown>[];
	providers?: Provider[];
	/**
	 * The credential providers the app registers.
	 * @default `defaultAuthProviders(auth)`: session, and JWT and API key with their plugins
	 */
	authProviders?: Provider[];
	imports?: (DynamicModule | Type<unknown>)[];
	authentication?: AuthenticationModuleOptions;
	/** Import `AuthorizationModule` (deny-by-default). */
	authorization?: boolean;
	/** Apollo's `GraphQLModule`, on `/graphql`. */
	graphql?: boolean;
	/** Another `GraphQLModule` than `graphql`'s (another driver, a subgraph). */
	graphqlModule?: DynamicModule;
	globalPrefix?: string;
	/**
	 * Keep Nest's own body parser, as an app with `routes: false` does.
	 * @default false
	 */
	nestBodyParser?: boolean;
	/** Listen on a random port, for clients other than supertest (socket.io). */
	listen?: boolean;
	/** The WebSocket adapter, e.g. `(app) => new WsAdapter(app)`; socket.io's by default. */
	webSocketAdapter?: (app: INestApplication) => WebSocketAdapter;
}

/**
 * Apollo's `context`, with the response the session provider sends its
 * cookies through: Apollo calls it with `{ req, res }` on Express, but with
 * `(request, reply)` on Fastify.
 */
export const apolloContext = (
	first: { req: Request; res: Response } | object,
	reply?: object,
) =>
	process.env.TEST_HTTP_ADAPTER === "fastify"
		? { req: first, reply }
		: { ...(first as { req: Request; res: Response }) };

/** An app with `AuthenticationModule` and `BetterAuthModule`, initialized on the adapter under test. */
export async function createTestApp(options: TestAppOptions) {
	const { auth } = options;

	@Module({
		imports: [
			AuthenticationModule.forRoot(options.authentication ?? {}),
			...(options.authorization ? [AuthorizationModule.forRoot()] : []),
			options.betterAuthModule ??
				BetterAuthModule.forRoot({ auth, ...options.module }),
			...(options.graphql
				? [
						GraphQLModule.forRoot<ApolloDriverConfig>({
							driver: ApolloDriver,
							autoSchemaFile: true,
							path: "/graphql",
							context: apolloContext,
						}),
					]
				: []),
			...(options.graphqlModule ? [options.graphqlModule] : []),
			...(options.imports ?? []),
		],
		controllers: options.controllers ?? [TestController],
		providers: [
			...(options.authProviders ?? defaultAuthProviders(auth)),
			...(options.providers ?? []),
		],
	})
	class AppModule {}

	const moduleRef = await Test.createTestingModule({
		imports: [AppModule],
	}).compile();

	// Better Auth parses its own bodies: Nest's parser must be off, unless
	// the app serves none of its routes.
	const app: INestApplication = moduleRef.createNestApplication(
		createTestHttpAdapter(),
		{ bodyParser: options.nestBodyParser ?? false, logger: false },
	);
	if (options.globalPrefix) app.setGlobalPrefix(options.globalPrefix);
	if (options.webSocketAdapter)
		app.useWebSocketAdapter(options.webSocketAdapter(app));

	if (options.listen) await app.listen(0);
	else await initTestApplication(app);

	return { app, auth, moduleRef };
}

let counter = 0;
/** An email address no earlier test used. */
export const uniqueEmail = () => `user-${Date.now()}-${counter++}@example.com`;

/** Signs up a user with a fresh email, returning Better Auth's result (with the bearer token). */
export async function signUp(
	auth: TestAuth,
	body: Partial<{ name: string; email: string; password: string }> = {},
) {
	return auth.api.signUpEmail({
		body: {
			name: "Test User",
			email: uniqueEmail(),
			password: "password-123456",
			...body,
		},
	});
}

/** Marks the user's email as verified. */
export async function verifyEmail(auth: TestAuth, userId: string) {
	const ctx = await auth.$context;
	await ctx.internalAdapter.updateUser(userId, { emailVerified: true });
}
