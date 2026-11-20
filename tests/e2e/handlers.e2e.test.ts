import { Injectable } from "@nestjs/common";
import request from "supertest";
import {
	AuthenticationRegistry,
	type EmailVerificationLink,
	type MagicLink,
	PasswordHasher,
	PasswordResetHandler,
	type PasswordResetLink,
	PasswordResetService,
} from "@nestjs/authentication";
import { magicLink } from "better-auth/plugins/magic-link";
import { twoFactor } from "better-auth/plugins/two-factor";
import { hashPassword } from "better-auth/crypto";
import {
	BetterAuthEmailVerificationHandler,
	BetterAuthMagicLinkHandler,
	BetterAuthPasswordResetHandler,
	BetterAuthService,
} from "../../src/index.ts";
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
import { withEnv } from "../shared/env.ts";

/** Records the passw/** The app's pages for Better Auth's links: the `url` of each AuthenticationModule feature. */
const pages = {
	passwordReset: { url: "http://app.test/reset-password" },
	emailVerification: { url: "http://app.test/verify-email" },
	magicLink: { url: "http://app.test/sign-in/magic" },
};

/** The `?token=` of a link a handler sent, checking it goes to `page`. */
function tokenOf(link: string, page: string): string {
	const url = new URL(link);
	expect(`${url.origin}${url.pathname}`).toBe(page);
	const token = url.searchParams.get("token");
	expect(token).toBeTruthy();
	return token as string;
}

/** Records the password reset links it is asked to send. */
@Injectable()
class TestPasswordResetHandler extends BetterAuthPasswordResetHandler {
	readonly sent: PasswordResetLink[] = [];
	constructor(registry: AuthenticationRegistry, betterAuth: BetterAuthService) {
		super(registry, betterAuth);
		registry.registerHandler("passwordReset", this);
	}
	send(link: PasswordResetLink) {
		this.sent.push(link);
	}
}

/**
 * Takes over `passwordReset` from `TestPasswordResetHandler`, as a wrapper
 * or a test double would: injecting it makes Nest create it first.
 */
@Injectable()
class ReplacingPasswordResetHandler extends BetterAuthPasswordResetHandler {
	readonly sent: PasswordResetLink[] = [];
	constructor(
		registry: AuthenticationRegistry,
		betterAuth: BetterAuthService,
		_first: TestPasswordResetHandler,
	) {
		super(registry, betterAuth);
		registry.registerHandler("passwordReset", this, { replace: true });
	}
	send(link: PasswordResetLink) {
		this.sent.push(link);
	}
}

/** A plain Nest handler: Better Auth would never call it. */
@Injectable()
class PlainPasswordResetHandler extends PasswordResetHandler {
	constructor(registry: AuthenticationRegistry) {
		super();
		registry.registerHandler("passwordReset", this);
	}
	findUser() {
		return null;
	}
	send() {}
	updatePassword() {}
}

/** Records the verification links it is asked to send. */
@Injectable()
class TestEmailVerificationHandler extends BetterAuthEmailVerificationHandler {
	readonly sent: EmailVerificationLink[] = [];
	constructor(registry: AuthenticationRegistry, betterAuth: BetterAuthService) {
		super(registry, betterAuth);
		registry.registerHandler("emailVerification", this);
	}
	send(link: EmailVerificationLink) {
		this.sent.push(link);
	}
}

/** Records the magic links it is asked to send. */
@Injectable()
class TestMagicLinkHandler extends BetterAuthMagicLinkHandler {
	readonly sent: MagicLink[] = [];
	constructor(registry: AuthenticationRegistry, betterAuth: BetterAuthService) {
		super(registry, betterAuth);
		registry.registerHandler("magicLink", this);
	}
	send(link: MagicLink) {
		this.sent.push(link);
	}
}

describe("handlers e2e: email handlers", () => {
	it("sends the app's reset page with Better Auth's token, which resets the password", async () => {
		const originalSend = vi.fn();
		const auth = createTestAuth({
			emailAndPassword: { enabled: true, sendResetPassword: originalSend },
		});
		const { app } = await createTestApp({
			auth,
			authentication: { passwordReset: pages.passwordReset },
			controllers: [],
			providers: [TestPasswordResetHandler],
		});

		try {
			const { user } = await signUp(auth);
			await auth.api.requestPasswordReset({
				body: { email: user.email, redirectTo: "http://app.test/signed-in" },
			});

			const [link] = app.get(TestPasswordResetHandler).sent;
			expect(link).toMatchObject({ userId: user.id, email: user.email });
			expect(link.expiresAt.getTime()).toBeGreaterThan(Date.now());
			// Better Auth's callbackURL rides along, for the page to use.
			expect(new URL(link.url).searchParams.get("callbackURL")).toBe(
				"http://app.test/signed-in",
			);
			// The Nest handler overrides the config's callback instead of composing: one email.
			expect(originalSend).not.toHaveBeenCalled();

			// What the page does: post the token and the new password to Better Auth.
			const server = app.getHttpServer();
			await request(server)
				.post("/api/auth/reset-password")
				.send({
					token: tokenOf(link.url, pages.passwordReset.url),
					newPassword: "a-brand-new-password",
				})
				.expect(200);
			await request(server)
				.post("/api/auth/sign-in/email")
				.send({ email: user.email, password: "a-brand-new-password" })
				.expect(200);
		} finally {
			await app.close();
		}
	});

	it("sends the app's verification page with Better Auth's token, which verifies the address", async () => {
		const auth = createTestAuth({ emailVerification: {} });
		const { app } = await createTestApp({
			auth,
			authentication: { emailVerification: pages.emailVerification },
			controllers: [],
			providers: [TestEmailVerificationHandler],
		});

		try {
			const { user } = await signUp(auth);
			await auth.api.sendVerificationEmail({ body: { email: user.email } });

			const link = app.get(TestEmailVerificationHandler).sent.at(-1);
			expect(link).toMatchObject({ userId: user.id, email: user.email });

			// What the page does: hand the token to Better Auth.
			const token = tokenOf(link?.url ?? "", pages.emailVerification.url);
			await request(app.getHttpServer())
				.get("/api/auth/verify-email")
				.query({ token })
				.expect(200);
			const ctx = await auth.$context;
			expect(
				(await ctx.internalAdapter.findUserById(user.id))?.emailVerified,
			).toBe(true);
		} finally {
			await app.close();
		}
	});

	it("sends the app's magic link page with Better Auth's token, which signs the user in", async () => {
		const auth = createTestAuth({
			baseURL: "http://localhost:3000",
			plugins: [magicLink({ sendMagicLink: fromNestHandler })],
		});
		const { app } = await createTestApp({
			auth,
			authentication: { magicLink: pages.magicLink },
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
			expect(handler.sent[0].email).toBe(email);

			// What the page does: hand the token to Better Auth.
			const token = tokenOf(handler.sent[0].url, pages.magicLink.url);
			const response = await request(app.getHttpServer())
				.get("/api/auth/magic-link/verify")
				.query({ token });
			expect(String(response.headers["set-cookie"])).toContain("session_token");
		} finally {
			await app.close();
		}
	});

	it("fails at startup when the parent config is missing", async () => {
		const auth = createTestAuth({ emailAndPassword: undefined });

		await expect(
			createTestApp({
				auth,
				authentication: { passwordReset: pages.passwordReset },
				controllers: [],
				providers: [TestPasswordResetHandler],
			}),
		).rejects.toThrow(/emailAndPassword/);
	});

	it("sends through whichever handler the registry holds", async () => {
		const auth = createTestAuth();
		const { app } = await createTestApp({
			auth,
			authentication: { passwordReset: pages.passwordReset },
			controllers: [],
			providers: [TestPasswordResetHandler, ReplacingPasswordResetHandler],
		});

		try {
			const { user } = await signUp(auth);
			await auth.api.requestPasswordReset({
				body: { email: user.email, redirectTo: "http://app.test/signed-in" },
			});

			expect(app.get(ReplacingPasswordResetHandler).sent).toHaveLength(1);
			expect(app.get(TestPasswordResetHandler).sent).toHaveLength(0);
		} finally {
			await app.close();
		}
	});

	it("refuses a plain Nest handler, which can't plug itself into Better Auth", async () => {
		await expect(
			createTestApp({
				auth: createTestAuth(),
				authentication: { passwordReset: pages.passwordReset },
				controllers: [],
				providers: [PlainPasswordResetHandler],
			}),
		).rejects.toThrow(/extend BetterAuthPasswordResetHandler/);
	});

	it("puts Better Auth's own callback back when the app closes", async () => {
		const originalSend = vi.fn();
		const auth = createTestAuth({
			emailAndPassword: { enabled: true, sendResetPassword: originalSend },
		});
		const { app } = await createTestApp({
			auth,
			authentication: { passwordReset: pages.passwordReset },
			controllers: [],
			providers: [TestPasswordResetHandler],
		});
		expect(auth.options.emailAndPassword?.sendResetPassword).not.toBe(
			originalSend,
		);
		await app.close();
		expect(auth.options.emailAndPassword?.sendResetPassword).toBe(originalSend);
	});

	it("needs its feature in the AuthenticationModule options, as every Nest handler", async () => {
		await expect(
			createTestApp({
				auth: createTestAuth(),
				controllers: [],
				providers: [TestPasswordResetHandler],
			}),
		).rejects.toThrow(/`passwordReset` option is missing/);
	});

	it("refuses Nest's options for the tokens: Better Auth's config sets them", async () => {
		await expect(
			createTestApp({
				auth: createTestAuth(),
				authentication: {
					passwordReset: { ...pages.passwordReset, ttl: "2h" },
				},
				controllers: [],
				providers: [TestPasswordResetHandler],
			}),
		).rejects.toThrow(/resetPasswordTokenExpiresIn/);
	});

	it("refuses Nest's own flow: Better Auth runs password resets", async () => {
		const auth = createTestAuth();
		const { app } = await createTestApp({
			auth,
			authentication: { passwordReset: pages.passwordReset },
			controllers: [],
			providers: [TestPasswordResetHandler],
		});

		try {
			await expect(
				// A well-formed token: Nest then reads its EmailTokenStore.
				app
					.get(PasswordResetService)
					.reset("a".repeat(43), "new-password-123"),
			).rejects.toThrow(/Better Auth/);
		} finally {
			await app.close();
		}
	});

	it("starts in production: the features' stores are Better Auth's, not in memory", async () => {
		await withEnv({ NODE_ENV: "production" }, async () => {
			const auth = createTestAuth({
				emailVerification: {},
				plugins: [magicLink({ sendMagicLink: fromNestHandler })],
			});
			const { app } = await createTestApp({
				auth,
				authentication: pages,
				controllers: [],
				providers: [
					TestPasswordResetHandler,
					TestEmailVerificationHandler,
					TestMagicLinkHandler,
				],
			});
			await app.close();
		});
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
