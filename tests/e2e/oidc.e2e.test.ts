import { Injectable } from "@nestjs/common";
import {
	type AuthenticationModuleOptions,
	AuthenticationRegistry,
	type OidcProfile,
	type OidcResolveContext,
} from "@nestjs/authentication";
import { genericOAuth } from "better-auth/plugins/generic-oauth";
import request from "supertest";
import {
	BetterAuthOidcAccountResolver,
	BetterAuthService,
	type BetterAuthUser,
} from "../../src/index.ts";
import { createTestApp, createTestAuth, uniqueEmail } from "../shared/app.ts";
import { withEnv } from "../shared/env.ts";

/** What the fake provider answers for the next sign-in. */
let identity: {
	id: string;
	email: string;
	emailVerified: boolean;
	name: string;
};

/** A provider without a network: Better Auth runs its whole OAuth flow on it. */
const acme = genericOAuth({
	config: [
		{
			providerId: "acme",
			clientId: "client-id",
			clientSecret: "client-secret",
			authorizationUrl: "http://idp.test/authorize",
			getToken: async () => ({ accessToken: "access-token" }),
			getUserInfo: async () => ({ ...identity }),
		},
	],
});

/** Records what it is asked, and confirms or refuses as configured. */
@Injectable()
class TestResolver extends BetterAuthOidcAccountResolver {
	readonly calls: Array<[OidcProfile, OidcResolveContext]> = [];
	refuse = false;
	constructor(registry: AuthenticationRegistry, betterAuth: BetterAuthService) {
		super(registry, betterAuth);
		registry.registerHandler("oidc", this);
	}
	resolveUser(
		profile: OidcProfile,
		_tokens: unknown,
		context: OidcResolveContext,
	) {
		this.calls.push([profile, context]);
		if (this.refuse) return null;
		return context.linkTo ?? { id: this.userIdFor(profile) };
	}
	/** The user Better Auth chose, as an app would look it up. */
	userIdFor = (_profile: OidcProfile) => "";
}

const oidc: AuthenticationModuleOptions["oidc"] = {
	callbackUrl: "http://localhost:3000/api/auth/callback/:provider",
	providers: () => null,
};

describe("OidcAccountResolver e2e, through Better Auth's OAuth flow", () => {
	const setup = async (
		authentication: AuthenticationModuleOptions = { oidc },
	) => {
		const auth = createTestAuth({
			baseURL: "http://localhost:3000",
			emailVerification: {},
			plugins: [acme],
		});
		const { app } = await createTestApp({
			auth,
			authentication,
			controllers: [],
			providers: [TestResolver],
		});
		const agent = request.agent(app.getHttpServer());
		const resolver = app.get(TestResolver);
		const ctx = await auth.$context;
		resolver.userIdFor = (profile) => profile.email ?? "";
		return { app, auth, agent, resolver, ctx };
	};

	/** Starts at `path` (sign-in or link) and follows the provider's redirect back to the callback. */
	const viaProvider = async (
		agent: ReturnType<typeof request.agent>,
		path: "/api/auth/sign-in/social" | "/api/auth/link-social",
	) => {
		const start = await agent
			.post(path)
			.send({ provider: "acme", callbackURL: "/done" })
			.expect(200);
		const state = new URL(start.body.url).searchParams.get("state");
		const callback = await agent
			.get("/api/auth/callback/acme")
			.query({ code: "code", state })
			.expect(302);
		return new URL(
			callback.headers.location as string,
			"http://localhost:3000",
		);
	};

	/** A user who signed up with a password and verified the address, through Better Auth's endpoints. */
	const verifiedUser = async ({
		auth,
		ctx,
	}: Awaited<ReturnType<typeof setup>>) => {
		const { user } = await auth.api.signUpEmail({
			body: {
				name: "Verified",
				email: uniqueEmail(),
				password: "password-123456",
			},
		});
		await ctx.internalAdapter.updateUser(user.id, { emailVerified: true });
		return user;
	};

	it("confirms the user Better Auth links a provider to by email", async () => {
		const env = await setup();
		const { app, agent, resolver, ctx } = env;
		try {
			const user = await verifiedUser(env);
			resolver.userIdFor = () => user.id;
			identity = {
				id: "acme-1",
				email: user.email,
				emailVerified: true,
				name: "A",
			};

			const landed = await viaProvider(agent, "/api/auth/sign-in/social");
			expect(landed.pathname).toBe("/done");
			expect(resolver.calls[0][0]).toMatchObject({
				provider: "acme",
				subject: "acme-1",
				email: user.email,
				emailVerified: true,
			});
			const accounts = await ctx.internalAdapter.findAccounts(user.id);
			expect(accounts.map((account) => account.providerId)).toContain("acme");
		} finally {
			await app.close();
		}
	});

	it("refuses the link when the resolver does: Better Auth stores nothing", async () => {
		const env = await setup();
		const { app, agent, resolver, ctx } = env;
		try {
			const user = await verifiedUser(env);
			resolver.refuse = true;
			identity = {
				id: "acme-2",
				email: user.email,
				emailVerified: true,
				name: "A",
			};

			const landed = await viaProvider(agent, "/api/auth/sign-in/social");
			expect(landed.searchParams.get("error")).toBe("account_link_refused");
			const accounts = await ctx.internalAdapter.findAccounts(user.id);
			expect(accounts.map((account) => account.providerId)).not.toContain(
				"acme",
			);
		} finally {
			await app.close();
		}
	});

	it("is asked again at each sign-in with the linked provider", async () => {
		const env = await setup();
		const { app, agent, resolver } = env;
		try {
			const user = await verifiedUser(env);
			resolver.userIdFor = () => user.id;
			identity = {
				id: "acme-3",
				email: user.email,
				emailVerified: true,
				name: "A",
			};
			await viaProvider(agent, "/api/auth/sign-in/social");

			resolver.refuse = true;
			const landed = await viaProvider(agent, "/api/auth/sign-in/social");
			expect(landed.searchParams.get("error")).toBe("account_link_refused");
			expect(resolver.calls).toHaveLength(2);
		} finally {
			await app.close();
		}
	});

	it("passes linkTo when a signed-in user connects a provider", async () => {
		const { app, agent, resolver, ctx } = await setup();
		try {
			const email = uniqueEmail();
			const signUp = await agent
				.post("/api/auth/sign-up/email")
				.send({ name: "Linker", email, password: "password-123456" })
				.expect(200);
			const userId = signUp.body.user.id as string;
			identity = { id: "acme-4", email, emailVerified: true, name: "L" };

			const landed = await viaProvider(agent, "/api/auth/link-social");
			expect(landed.pathname).toBe("/done");
			expect(resolver.calls[0][1]).toEqual({ linkTo: { id: userId } });
			const accounts = await ctx.internalAdapter.findAccounts(userId);
			expect(accounts.map((account) => account.providerId)).toContain("acme");
		} finally {
			await app.close();
		}
	});

	it("leaves new identities to Better Auth's sign-up options", async () => {
		const { app, agent, resolver } = await setup();
		try {
			identity = {
				id: "acme-5",
				email: uniqueEmail(),
				emailVerified: true,
				name: "New",
			};
			const landed = await viaProvider(agent, "/api/auth/sign-in/social");
			expect(landed.pathname).toBe("/done");
			expect(resolver.calls).toHaveLength(0);
		} finally {
			await app.close();
		}
	});

	it("runs after the config's own validateUserInfo, which can refuse first", async () => {
		const validateUserInfo = vi.fn(async () => ({
			error: "domain_not_allowed",
		}));
		const auth = createTestAuth({
			baseURL: "http://localhost:3000",
			plugins: [acme],
			user: { validateUserInfo },
		});
		const { app } = await createTestApp({
			auth,
			authentication: { oidc },
			controllers: [],
			providers: [TestResolver],
		});
		try {
			const agent = request.agent(app.getHttpServer());
			identity = {
				id: "acme-6",
				email: uniqueEmail(),
				emailVerified: true,
				name: "D",
			};
			const landed = await viaProvider(agent, "/api/auth/sign-in/social");
			expect(landed.searchParams.get("error")).toBe("domain_not_allowed");
			expect(validateUserInfo).toHaveBeenCalled();
		} finally {
			await app.close();
		}
	});

	it("needs Better Auth's callback as oidc.callbackUrl", async () => {
		await expect(
			setup({
				oidc: {
					...oidc,
					callbackUrl: "http://localhost:3000/auth/oidc/:provider/callback",
				},
			}),
		).rejects.toThrow(/\/api\/auth\/callback\/:provider/);
	});

	it("refuses Nest's own OIDC providers: Better Auth's socialProviders sign users in", async () => {
		await expect(
			setup({
				oidc: {
					...oidc,
					providers: {
						acme: {
							issuer: "https://idp.test",
							clientId: "id",
							clientSecret: "secret",
						},
					},
				},
			}),
		).rejects.toThrow(/providers: \(\) => null/);
	});

	it("starts in production: the oidc feature's stores are Better Auth's", async () => {
		await withEnv({ NODE_ENV: "production" }, async () => {
			const { app } = await setup();
			await app.close();
		});
	});

	describe("BetterAuthOidcAccountResolver's defaults", () => {
		/** Only registers itself: every method keeps its default. */
		@Injectable()
		class DefaultResolver extends BetterAuthOidcAccountResolver {
			constructor(
				registry: AuthenticationRegistry,
				betterAuth: BetterAuthService,
			) {
				super(registry, betterAuth);
				registry.registerHandler("oidc", this);
			}
		}

		/** The app's rule on top of the default lookup: `validate()` gets the whole user. */
		@Injectable()
		class ValidatingResolver extends DefaultResolver {
			readonly validated: BetterAuthUser[] = [];
			protected override validate(user: BetterAuthUser) {
				this.validated.push(user);
				return user.name === "Blocked" ? null : user;
			}
		}

		/** Looks users up in a repository of its own, which here disagrees with Better Auth. */
		@Injectable()
		class RepositoryResolver extends DefaultResolver {
			protected override async findUserId() {
				return "someone-else";
			}
		}

		const setupWith = async (resolver: new (...args: never[]) => unknown) => {
			const auth = createTestAuth({
				baseURL: "http://localhost:3000",
				emailVerification: {},
				plugins: [acme],
			});
			const { app } = await createTestApp({
				auth,
				authentication: { oidc },
				controllers: [],
				providers: [resolver as never],
			});
			const env = {
				app,
				auth,
				agent: request.agent(app.getHttpServer()),
				ctx: await auth.$context,
			};
			return env;
		};

		const signUpVerified = async (
			env: Awaited<ReturnType<typeof setupWith>>,
			name = "Verified",
		) => {
			const { user } = await env.auth.api.signUpEmail({
				body: { name, email: uniqueEmail(), password: "password-123456" },
			});
			await env.ctx.internalAdapter.updateUser(user.id, {
				emailVerified: true,
			});
			return user;
		};

		const providers = async (
			env: Awaited<ReturnType<typeof setupWith>>,
			userId: string,
		) =>
			(await env.ctx.internalAdapter.findAccounts(userId)).map(
				(account) => account.providerId,
			);

		it("confirms Better Auth's choice: the address's user, then the provider account's owner", async () => {
			const env = await setupWith(DefaultResolver);
			try {
				const user = await signUpVerified(env);
				identity = {
					id: "acme-d1",
					email: user.email,
					emailVerified: true,
					name: "A",
				};
				const linked = await viaProvider(env.agent, "/api/auth/sign-in/social");
				expect(linked.pathname).toBe("/done");
				expect(await providers(env, user.id)).toContain("acme");

				// Signed in again with the linked provider: found by its account.
				const again = await viaProvider(
					request.agent(env.app.getHttpServer()),
					"/api/auth/sign-in/social",
				);
				expect(again.pathname).toBe("/done");
			} finally {
				await env.app.close();
			}
		});

		it("confirms the signed-in user who connects a provider (linkTo)", async () => {
			const env = await setupWith(DefaultResolver);
			try {
				const email = uniqueEmail();
				const signedUp = await env.agent
					.post("/api/auth/sign-up/email")
					.send({ name: "Linker", email, password: "password-123456" })
					.expect(200);
				identity = { id: "acme-d2", email, emailVerified: true, name: "L" };

				const landed = await viaProvider(env.agent, "/api/auth/link-social");
				expect(landed.pathname).toBe("/done");
				expect(await providers(env, signedUp.body.user.id)).toContain("acme");
			} finally {
				await env.app.close();
			}
		});

		it("hands validate() the whole user, and refuses what it refuses", async () => {
			const env = await setupWith(ValidatingResolver);
			try {
				const blocked = await signUpVerified(env, "Blocked");
				identity = {
					id: "acme-d3",
					email: blocked.email,
					emailVerified: true,
					name: "B",
				};
				const landed = await viaProvider(env.agent, "/api/auth/sign-in/social");
				expect(landed.searchParams.get("error")).toBe("account_link_refused");
				expect(await providers(env, blocked.id)).not.toContain("acme");
				expect(env.app.get(ValidatingResolver).validated.at(-1)).toMatchObject({
					id: blocked.id,
					email: blocked.email,
					name: "Blocked",
				});
			} finally {
				await env.app.close();
			}
		});

		it("refuses when a repository of the app's finds another user than Better Auth", async () => {
			const env = await setupWith(RepositoryResolver);
			try {
				const user = await signUpVerified(env);
				identity = {
					id: "acme-d4",
					email: user.email,
					emailVerified: true,
					name: "R",
				};
				const landed = await viaProvider(env.agent, "/api/auth/sign-in/social");
				expect(landed.searchParams.get("error")).toBe("account_link_refused");
			} finally {
				await env.app.close();
			}
		});
	});
});
