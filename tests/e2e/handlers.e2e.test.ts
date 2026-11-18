import { Injectable } from "@nestjs/common";
import request from "supertest";
import {
	EmailVerificationHandler,
	type EmailVerificationLink,
	MagicLinkHandler,
	type MagicLink,
	OidcAccountResolver,
	PasswordHasher,
	PasswordResetHandler,
	type PasswordResetLink,
} from "@nestjs/authentication";
import { magicLink } from "better-auth/plugins/magic-link";
import { twoFactor } from "better-auth/plugins/two-factor";
import { hashPassword } from "better-auth/crypto";
import {
	betterAuthPassword,
	fromNestHandler,
	nestPasswordHasher,
} from "../../src/plugin/index.ts";
import {
	createTestApp,
	createTestAuth,
	signUp,
	uniqueEmail,
} from "../shared/app.ts";

/** Records the password reset links it is asked to send. */
@Injectable()
class TestPasswordResetHandler extends PasswordResetHandler {
	readonly sent: PasswordResetLink[] = [];
	findUser() {
		return null;
	}
	send(link: PasswordResetLink) {
		this.sent.push(link);
	}
	updatePassword() {}
}

/** Records the verification links it is asked to send. */
@Injectable()
class TestEmailVerificationHandler extends EmailVerificationHandler {
	readonly sent: EmailVerificationLink[] = [];
	send(link: EmailVerificationLink) {
		this.sent.push(link);
	}
	markVerified() {
		return true;
	}
}

/** Records the magic links it is asked to send. */
@Injectable()
class TestMagicLinkHandler extends MagicLinkHandler {
	readonly sent: MagicLink[] = [];
	send(link: MagicLink) {
		this.sent.push(link);
	}
	resolveUser() {
		return null;
	}
}

describe("handlers e2e: email handlers", () => {
	it("sends password reset links through the discovered PasswordResetHandler", async () => {
		const originalSend = vi.fn();
		const auth = createTestAuth({
			emailAndPassword: { enabled: true, sendResetPassword: originalSend },
		});
		const { app } = await createTestApp({
			auth,
			controllers: [],
			providers: [TestPasswordResetHandler],
		});

		try {
			const { user } = await signUp(auth);
			await auth.api.requestPasswordReset({
				body: { email: user.email, redirectTo: "http://localhost/reset" },
			});

			const handler = app.get(TestPasswordResetHandler);
			expect(handler.sent).toHaveLength(1);
			expect(handler.sent[0]).toMatchObject({
				userId: user.id,
				email: user.email,
				url: expect.stringContaining("reset-password"),
			});
			expect(handler.sent[0].expiresAt.getTime()).toBeGreaterThan(Date.now());
			// The Nest handler overrides the config's callback instead of composing: one email.
			expect(originalSend).not.toHaveBeenCalled();
		} finally {
			await app.close();
		}
	});

	it("sends verification links through the discovered EmailVerificationHandler", async () => {
		const auth = createTestAuth({ emailVerification: {} });
		const { app } = await createTestApp({
			auth,
			controllers: [],
			providers: [TestEmailVerificationHandler],
		});

		try {
			const { user } = await signUp(auth);
			await auth.api.sendVerificationEmail({ body: { email: user.email } });

			const handler = app.get(TestEmailVerificationHandler);
			expect(handler.sent.at(-1)).toMatchObject({
				userId: user.id,
				email: user.email,
				url: expect.stringContaining("verify-email"),
			});
		} finally {
			await app.close();
		}
	});

	it("sends magic links through the discovered MagicLinkHandler", async () => {
		const auth = createTestAuth({
			baseURL: "http://localhost:3000",
			plugins: [magicLink({ sendMagicLink: fromNestHandler })],
		});
		const { app } = await createTestApp({
			auth,
			controllers: [],
			providers: [TestMagicLinkHandler],
		});

		try {
			const email = uniqueEmail();
			// biome-ignore lint/suspicious/noExplicitAny: the magic-link endpoints are not typed on the generic auth instance
			await (auth.api as any).signInMagicLink({
				body: { email },
				headers: new Headers(),
			});

			const handler = app.get(TestMagicLinkHandler);
			expect(handler.sent).toHaveLength(1);
			expect(handler.sent[0]).toMatchObject({
				email,
				url: expect.stringContaining("magic-link"),
			});
		} finally {
			await app.close();
		}
	});

	it("fails at startup when the parent config is missing", async () => {
		const auth = createTestAuth({ emailAndPassword: undefined });

		await expect(
			createTestApp({
				auth,
				controllers: [],
				providers: [TestPasswordResetHandler],
			}),
		).rejects.toThrow(/emailAndPassword/);
	});

	it("does not require Nest's own password reset feature to be configured", async () => {
		// AuthenticationModule.forRoot() has no `passwordReset` option here, which
		// would make the registry refuse a registered handler.
		const auth = createTestAuth();
		const { app } = await createTestApp({
			auth,
			controllers: [],
			providers: [TestPasswordResetHandler],
		});
		await app.close();
	});
});

describe("handlers e2e: OidcAccountResolver", () => {
	/** Records what it is asked to resolve, and allows or refuses links as configured. */
	@Injectable()
	class TestOidcResolver extends OidcAccountResolver {
		readonly calls: unknown[][] = [];
		allow = true;
		resolveUser(...args: [unknown, unknown, unknown]) {
			this.calls.push(args);
			return this.allow
				? { id: (args[0] as { subject: string }).subject }
				: null;
		}
	}

	/** Links a GitHub account to `userId`, which runs the account `before` hook. */
	const linkGithub = async (
		auth: ReturnType<typeof createTestAuth>,
		userId: string,
		accountId: string,
	) => {
		const ctx = await auth.$context;
		return ctx.internalAdapter.linkAccount({
			userId,
			providerId: "github",
			accountId,
			accessToken: "token",
		});
	};

	it("lets the resolver decide which user an external identity links to", async () => {
		const auth = createTestAuth();
		const { app } = await createTestApp({
			auth,
			controllers: [],
			providers: [TestOidcResolver],
		});

		try {
			const { user } = await signUp(auth);
			const resolver = app.get(TestOidcResolver);

			// Resolves to the same user: allowed.
			expect(await linkGithub(auth, user.id, user.id)).toBeTruthy();
			expect(resolver.calls[0][0]).toMatchObject({
				provider: "github",
				subject: user.id,
				email: user.email,
			});
			expect(resolver.calls[0][1]).toMatchObject({ accessToken: "token" });

			// Resolves to somebody else, or to nobody: refused with an error, which
			// also stops Better Auth from creating a new user without the account.
			const other = await signUp(auth);
			await expect(
				linkGithub(auth, other.user.id, "someone-else"),
			).rejects.toMatchObject({ statusCode: 403 });
			resolver.allow = false;
			await expect(
				linkGithub(auth, other.user.id, "unknown"),
			).rejects.toMatchObject({ statusCode: 403 });
			const accounts = await (await auth.$context).internalAdapter.findAccounts(
				other.user.id,
			);
			expect(accounts.map((account) => account.providerId)).toEqual([
				"credential",
			]);
		} finally {
			await app.close();
		}
	});

	it("composes with the config's own databaseHooks", async () => {
		const before = vi.fn();
		const auth = createTestAuth({
			databaseHooks: { account: { create: { before } } },
		});
		const { app } = await createTestApp({
			auth,
			controllers: [],
			providers: [TestOidcResolver],
		});

		try {
			const { user } = await signUp(auth);
			await linkGithub(auth, user.id, user.id);
			expect(before).toHaveBeenCalled();
		} finally {
			await app.close();
		}
	});
});

describe("handlers e2e: PasswordHasher bridge", () => {
	const authenticationOptions = { password: { logN: 10 } };
	const password = "password-123456";

	/** The stored hash of a user's credential account. */
	const credentialPassword = async (
		auth: ReturnType<typeof createTestAuth>,
		userId: string,
	) => {
		const ctx = await auth.$context;
		const accounts = await ctx.internalAdapter.findAccounts(userId);
		return accounts.find((a) => a.providerId === "credential")?.password;
	};

	/** A user whose credential holds a hash in Better Auth's own `salt:key` format. */
	const legacyUser = async (auth: ReturnType<typeof createTestAuth>) => {
		const ctx = await auth.$context;
		const email = uniqueEmail();
		const user = await ctx.internalAdapter.createUser(
			{ name: "Legacy", email },
			{ method: "admin" },
		);
		const legacyHash = await hashPassword(password);
		await ctx.internalAdapter.linkAccount({
			userId: user.id,
			providerId: "credential",
			accountId: user.id,
			password: legacyHash,
		});
		return { email, user, legacyHash };
	};

	it("hashes with betterAuthPassword(hasher)", async () => {
		const hasher = new PasswordHasher({ logN: 10 });
		const auth = createTestAuth({
			emailAndPassword: {
				enabled: true,
				password: betterAuthPassword(hasher),
			},
		});
		const { app } = await createTestApp({ auth, controllers: [] });

		try {
			const { user } = await signUp(auth);
			expect(await credentialPassword(auth, user.id)).toMatch(/^\$scrypt\$/);

			const signedIn = await auth.api.signInEmail({
				body: { email: user.email, password },
			});
			expect(signedIn.user.id).toBe(user.id);
			await expect(
				auth.api.signInEmail({
					body: { email: user.email, password: "wrong-password" },
				}),
			).rejects.toThrow();
		} finally {
			await app.close();
		}
	});

	it("binds nestPasswordHasher() to the injected PasswordHasher", async () => {
		const auth = createTestAuth({
			emailAndPassword: { enabled: true, password: nestPasswordHasher() },
		});
		const { app } = await createTestApp({
			auth,
			controllers: [],
			authentication: authenticationOptions,
		});

		try {
			const { user } = await signUp(auth);
			expect(await credentialPassword(auth, user.id)).toMatch(
				/^\$scrypt\$ln=10,/,
			);
			await auth.api.signInEmail({ body: { email: user.email, password } });
		} finally {
			await app.close();
		}
	});

	it("verifies and rehashes Better Auth's legacy hashes on sign-in", async () => {
		const auth = createTestAuth({
			emailAndPassword: { enabled: true, password: nestPasswordHasher() },
		});
		const server = await createTestApp({
			auth,
			controllers: [],
			authentication: authenticationOptions,
		});

		try {
			const ctx = await auth.$context;
			const email = uniqueEmail();
			const user = await ctx.internalAdapter.createUser(
				{ name: "Legacy", email },
				{ method: "admin" },
			);
			const legacyHash = await hashPassword(password);
			await ctx.internalAdapter.linkAccount({
				userId: user.id,
				providerId: "credential",
				accountId: user.id,
				password: legacyHash,
			});
			expect(await credentialPassword(auth, user.id)).toBe(legacyHash);

			await request(server.app.getHttpServer())
				.post("/api/auth/sign-in/email")
				.send({ email, password })
				.expect(200);

			expect(await credentialPassword(auth, user.id)).toMatch(/^\$scrypt\$/);

			// The rehashed password still works.
			await request(server.app.getHttpServer())
				.post("/api/auth/sign-in/email")
				.send({ email, password })
				.expect(200);
		} finally {
			await server.app.close();
		}
	});

	it("never fails a sign-in over a hash upgrade error", async () => {
		const auth = createTestAuth({
			emailAndPassword: { enabled: true, password: nestPasswordHasher() },
		});
		const server = await createTestApp({
			auth,
			controllers: [],
			authentication: authenticationOptions,
		});

		try {
			const { email } = await legacyUser(auth);
			// The upgrade will fail, with a non-Error value even.
			const ctx = await auth.$context;
			vi.spyOn(ctx.adapter, "updateMany").mockRejectedValue(null);

			await request(server.app.getHttpServer())
				.post("/api/auth/sign-in/email")
				.send({ email, password })
				.expect(200);
		} finally {
			vi.restoreAllMocks();
			await server.app.close();
		}
	});

	it("upgrades the hash of a user whose sign-in twoFactor() challenges", async () => {
		const auth = createTestAuth({
			emailAndPassword: { enabled: true, password: nestPasswordHasher() },
			plugins: [twoFactor()],
		});
		const server = await createTestApp({
			auth,
			controllers: [],
			authentication: authenticationOptions,
		});

		try {
			const { email, user } = await legacyUser(auth);
			await (await auth.$context).internalAdapter.updateUser(user.id, {
				twoFactorEnabled: true,
			});

			const response = await request(server.app.getHttpServer())
				.post("/api/auth/sign-in/email")
				.send({ email, password })
				.expect(200);
			expect(response.body.twoFactorRedirect).toBe(true);
			expect(await credentialPassword(auth, user.id)).toMatch(/^\$scrypt\$/);
		} finally {
			await server.app.close();
		}
	});

	it("leaves alone a hash that changed since it was read", async () => {
		const auth = createTestAuth({
			emailAndPassword: { enabled: true, password: nestPasswordHasher() },
		});
		const server = await createTestApp({
			auth,
			controllers: [],
			authentication: authenticationOptions,
		});

		try {
			const { user, legacyHash } = await legacyUser(auth);
			// A password reset lands between the read and the upgrade.
			const ctx = await auth.$context;
			await ctx.internalAdapter.updatePassword(user.id, "changed-meanwhile");

			const passwordConfig = auth.options.emailAndPassword?.password;
			expect(
				await passwordConfig?.verify?.({ hash: legacyHash, password }),
			).toBe(true);
			expect(await credentialPassword(auth, user.id)).toBe("changed-meanwhile");
		} finally {
			await server.app.close();
		}
	});

	it("rejects legacy hashes with legacyHashes: false", async () => {
		const hasher = new PasswordHasher({ logN: 10 });
		const { verify } = betterAuthPassword(hasher, { legacyHashes: false });
		const legacyHash = await hashPassword(password);

		expect(await verify({ hash: legacyHash, password })).toBe(false);
		expect(await verify({ hash: await hasher.hash(password), password })).toBe(
			true,
		);
	});

	it("throws a clear error when nestPasswordHasher() was never bound", async () => {
		const { hash } = nestPasswordHasher();
		await expect(hash("x")).rejects.toThrow(/not bound/);
	});

	it("starts with the placeholder once AuthenticationModule is imported", async () => {
		const auth = createTestAuth({
			emailAndPassword: { enabled: true, password: nestPasswordHasher() },
		});
		const { app } = await createTestApp({ auth, controllers: [] });
		await app.close();
	});
});
