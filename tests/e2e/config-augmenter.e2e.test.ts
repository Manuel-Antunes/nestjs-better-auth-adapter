import {
	Inject,
	Injectable,
	type OnModuleDestroy,
	type OnModuleInit,
} from "@nestjs/common";
import { magicLink } from "better-auth/plugins/magic-link";
import request from "supertest";
import {
	BetterAuthConfigAugmenter,
	BetterAuthService,
} from "../../src/index.ts";
import {
	createTestApp,
	createTestAuth,
	signUp,
	type TestAuth,
	verifyEmail,
} from "../shared/app.ts";

const ORIGIN = "http://localhost:3000";

type Mail = { to: string; subject: string; url: string };

/** Sends Better Auth's account mails through Nest, as an app would. */
@Injectable()
class AccountMails implements OnModuleInit, OnModuleDestroy {
	readonly sent: Mail[] = [];
	readonly #config: BetterAuthConfigAugmenter<TestAuth>;

	constructor(
		@Inject(BetterAuthService) betterAuth: BetterAuthService<TestAuth>,
	) {
		this.#config = new BetterAuthConfigAugmenter(betterAuth.instance)
			.replace(
				"user.changeEmail.sendChangeEmailConfirmation",
				async ({ user, newEmail, url }) => {
					this.sent.push({ to: user.email, subject: `to ${newEmail}`, url });
				},
			)
			.replace(
				"user.deleteUser.sendDeleteAccountVerification",
				async ({ user, url }) => {
					this.sent.push({ to: user.email, subject: "delete", url });
				},
			);
	}

	onModuleInit() {
		return this.#config.apply();
	}

	onModuleDestroy() {
		this.#config.restore();
	}
}

const pathOf = (link: string) => {
	const url = new URL(link);
	return `${url.pathname}${url.search}`;
};

describe("BetterAuthConfigAugmenter from a Nest provider", () => {
	const createAuth = () =>
		createTestAuth({
			baseURL: ORIGIN,
			// Better Auth sends a change confirmation only with verification on.
			emailVerification: { sendVerificationEmail: async () => {} },
			user: {
				changeEmail: { enabled: true },
				deleteUser: { enabled: true },
			},
		});

	it("sends the change of address confirmation through it", async () => {
		const auth = createAuth();
		const { app } = await createTestApp({
			auth,
			controllers: [],
			providers: [AccountMails],
		});
		try {
			const { user, token } = await signUp(auth);
			await verifyEmail(auth, user.id);
			await request(app.getHttpServer())
				.post("/api/auth/change-email")
				.set("Authorization", `Bearer ${token}`)
				.send({ newEmail: "new@example.com" })
				.expect(200);

			const [mail] = app.get(AccountMails).sent;
			expect(mail).toMatchObject({
				to: user.email,
				subject: "to new@example.com",
			});
			expect(new URL(mail?.url ?? "").pathname).toBe("/api/auth/verify-email");
		} finally {
			await app.close();
		}
	});

	it("sends the account deletion link through it, which deletes the account", async () => {
		const auth = createAuth();
		const { app } = await createTestApp({
			auth,
			controllers: [],
			providers: [AccountMails],
		});
		try {
			const server = app.getHttpServer();
			const { user, token } = await signUp(auth);
			await request(server)
				.post("/api/auth/delete-user")
				.set("Authorization", `Bearer ${token}`)
				.send({ callbackURL: "/goodbye" })
				.expect(200);

			const [mail] = app.get(AccountMails).sent;
			expect(mail).toMatchObject({ to: user.email, subject: "delete" });
			await request(server)
				.get(pathOf(mail?.url ?? ""))
				.set("Authorization", `Bearer ${token}`)
				.expect(302);
			const ctx = await auth.$context;
			expect(await ctx.internalAdapter.findUserById(user.id)).toBeNull();
		} finally {
			await app.close();
		}
	});

	it("puts the config's callbacks back when the app closes", async () => {
		const auth = createAuth();
		const { app } = await createTestApp({
			auth,
			controllers: [],
			providers: [AccountMails],
		});
		expect(
			auth.options.user?.changeEmail?.sendChangeEmailConfirmation,
		).toBeTypeOf("function");
		await app.close();
		expect(auth.options.user?.changeEmail).not.toHaveProperty(
			"sendChangeEmailConfirmation",
		);
		expect(auth.options.user?.deleteUser).not.toHaveProperty(
			"sendDeleteAccountVerification",
		);
	});
});

describe("BetterAuthConfigAugmenter", () => {
	const deletion = { user: { email: "a@example.com" }, url: "u", token: "t" };

	it("applies its changes in order, and restores them last first", async () => {
		const calls: string[] = [];
		const original = async () => {
			calls.push("config");
		};
		const auth = createTestAuth({
			user: {
				deleteUser: { enabled: true, sendDeleteAccountVerification: original },
			},
		});
		const config = new BetterAuthConfigAugmenter(auth)
			.wrap(
				"user.deleteUser.sendDeleteAccountVerification",
				(next) => async (data, request) => {
					calls.push("first");
					await next?.(data, request);
				},
			)
			.wrap(
				"user.deleteUser.sendDeleteAccountVerification",
				(next) => async (data, request) => {
					calls.push("second");
					await next?.(data, request);
				},
			);

		// Nothing changes before apply().
		expect(auth.options.user?.deleteUser?.sendDeleteAccountVerification).toBe(
			original,
		);
		await config.apply();
		await auth.options.user?.deleteUser?.sendDeleteAccountVerification?.(
			deletion as never,
		);
		expect(calls).toEqual(["second", "first", "config"]);

		config.restore();
		expect(auth.options.user?.deleteUser?.sendDeleteAccountVerification).toBe(
			original,
		);
	});

	it("reaches the endpoints: the context's copy of the options too", async () => {
		const auth = createTestAuth({
			user: { deleteUser: { enabled: true } },
		});
		const callback = async () => {};
		await new BetterAuthConfigAugmenter(auth)
			.replace("user.deleteUser.sendDeleteAccountVerification", callback)
			.apply();
		const { options } = await auth.$context;
		expect(options.user?.deleteUser?.sendDeleteAccountVerification).toBe(
			callback,
		);
	});

	it("changes the sections Better Auth copied into its context, in both", async () => {
		// Without a database, Better Auth merges `account` into a copy.
		const auth = createTestAuth({ account: { accountLinking: {} } });
		const { options } = await auth.$context;
		expect(options.account).not.toBe(auth.options.account);

		const callback = async () => {};
		const config = new BetterAuthConfigAugmenter(auth).replace(
			"account.accountLinking.onLink" as never,
			callback as never,
		);
		await config.apply();
		const linking = (section: unknown) =>
			(section as { accountLinking: Record<string, unknown> }).accountLinking;
		expect(linking(auth.options.account).onLink).toBe(callback);
		expect(linking(options.account).onLink).toBe(callback);

		config.restore();
		expect(linking(auth.options.account)).not.toHaveProperty("onLink");
		expect(linking(options.account)).not.toHaveProperty("onLink");
	});

	it("changes a section only the context has, as a plugin's init() adds", async () => {
		const auth = createTestAuth();
		const { options } = await auth.$context;
		// What a plugin's init() does: a section in the context's options only.
		const added = { deleteUser: { enabled: true } };
		Object.assign(options, { user: added });

		const callback = async () => {};
		const config = new BetterAuthConfigAugmenter(auth).replace(
			"user.deleteUser.beforeDelete",
			callback,
		);
		await config.apply();
		expect(added.deleteUser).toHaveProperty("beforeDelete", callback);
		expect(auth.options.user).toBeUndefined();

		config.restore();
		expect(added.deleteUser).not.toHaveProperty("beforeDelete");
	});

	it("fails on a section the instance doesn't configure, naming it", async () => {
		const auth = createTestAuth();
		await expect(
			new BetterAuthConfigAugmenter(auth)
				// Without `create`, the section must be configured.
				.replace(
					"user.deleteUser.sendDeleteAccountVerification",
					async () => {},
				)
				.apply(),
		).rejects.toThrow(
			"'user.deleteUser.sendDeleteAccountVerification' needs 'user' configured in Better Auth's options: a callback doesn't turn its feature on.",
		);
	});

	it("creates the missing sections with create: true, and removes them on restore", async () => {
		const auth = createTestAuth();
		const gate = async () => {};
		const config = new BetterAuthConfigAugmenter(auth).replace(
			"user.validateUserInfo",
			gate,
			{ create: true },
		);
		await config.apply();
		const { options } = await auth.$context;
		expect(auth.options.user?.validateUserInfo).toBe(gate);
		expect(options.user?.validateUserInfo).toBe(gate);

		config.restore();
		expect(auth.options.user).toBeUndefined();
		expect(options.user).toBeUndefined();
	});

	it("refuses a key holding something else than a callback", async () => {
		const auth = createTestAuth({ user: { changeEmail: { enabled: true } } });
		await expect(
			new BetterAuthConfigAugmenter(auth)
				.replace("user.changeEmail.enabled" as never, (async () => {}) as never)
				.apply(),
		).rejects.toThrow(
			"'user.changeEmail.enabled' in Better Auth's options holds a boolean, not a callback.",
		);
	});

	it.each([
		[
			"a path through the prototype",
			"user.__proto__.polluted",
			/isn't the path of a callback/,
		],
		[
			"a top-level option",
			"onAPIError",
			/top-level option, which Better Auth copies/,
		],
		[
			"something Better Auth calls",
			"secondaryStorage.get",
			/isn't Better Auth's config/,
		],
		["the plugins", "plugins.0", /reach a plugin's options with plugin\(\)/],
	])("refuses %s as soon as it's asked", (_, path, message) => {
		expect(() =>
			new BetterAuthConfigAugmenter(createTestAuth()).replace(
				path as never,
				(async () => {}) as never,
			),
		).toThrow(message);
		expect(Object.prototype).not.toHaveProperty("polluted");
	});

	it("changes a plugin's options, which the plugin reads", async () => {
		const sent: string[] = [];
		const auth = createTestAuth({
			baseURL: ORIGIN,
			plugins: [magicLink({ sendMagicLink: async () => {} })],
		});
		const config = new BetterAuthConfigAugmenter(auth).plugin(
			"magic-link",
			(plugin) =>
				plugin.replace(
					"sendMagicLink",
					async ({ email }: { email: string }) => {
						sent.push(email);
					},
				),
		);
		await config.apply();
		// biome-ignore lint/suspicious/noExplicitAny: the plugin's endpoints aren't typed on the test instance
		await (auth.api as any).signInMagicLink({
			body: { email: "magic@example.com" },
			headers: new Headers(),
		});
		expect(sent).toEqual(["magic@example.com"]);
		config.restore();
	});

	it("fails on a plugin the instance doesn't configure", async () => {
		await expect(
			new BetterAuthConfigAugmenter(createTestAuth())
				.plugin("magic-link", (plugin) =>
					plugin.replace("sendMagicLink", async () => {}),
				)
				.apply(),
		).rejects.toThrow(
			"'sendMagicLink' is in the magic-link plugin's options, but the plugin isn't configured.",
		);
	});

	it("leaves the changes before a failed one applied, for restore()", async () => {
		const original = async () => {};
		const auth = createTestAuth({
			user: {
				deleteUser: { enabled: true, sendDeleteAccountVerification: original },
			},
		});
		const config = new BetterAuthConfigAugmenter(auth)
			.replace("user.deleteUser.sendDeleteAccountVerification", async () => {})
			.replace("user.changeEmail.sendChangeEmailConfirmation", async () => {});
		await expect(config.apply()).rejects.toThrow(
			/needs 'user.changeEmail' configured/,
		);
		expect(
			auth.options.user?.deleteUser?.sendDeleteAccountVerification,
		).not.toBe(original);
		config.restore();
		expect(auth.options.user?.deleteUser?.sendDeleteAccountVerification).toBe(
			original,
		);
	});
});
