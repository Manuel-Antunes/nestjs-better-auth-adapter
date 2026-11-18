import {
	Inject,
	Injectable,
	Logger,
	type OnModuleDestroy,
	type OnModuleInit,
	Optional,
} from "@nestjs/common";
import { DiscoveryService } from "@nestjs/core";
import {
	AuthenticationRegistry,
	EmailVerificationHandler,
	MagicLinkHandler,
	OidcAccountResolver,
	PasswordHasher,
	PasswordResetHandler,
} from "@nestjs/authentication";
import { APIError } from "better-auth/api";
import {
	BETTER_AUTH_MODULE_OPTIONS,
	type BetterAuthModuleOptions,
} from "./better-auth.module-definition.ts";
import { addDatabaseHook } from "./hooks/database-hooks.ts";
import { bridgeOf, findPlugin } from "./plugins.ts";
import {
	BIND_PASSWORD_HASHER,
	type BetterAuthPassword,
} from "./plugin/password.ts";
import { PLACEHOLDER } from "./plugin/placeholders.ts";

// biome-ignore lint/suspicious/noExplicitAny: Better Auth's option objects vary by version and plugins
type Options = Record<string, any>;

/** A date `seconds` from now, for the links Better Auth hands to a callback. */
const expiresIn = (seconds: number): Date =>
	new Date(Date.now() + seconds * 1000);

/**
 * Plugs the `@nestjs/authentication` ports Better Auth can use into its
 * configuration, once Nest has created every provider: the email handlers
 * (`PasswordResetHandler`, `EmailVerificationHandler`, `MagicLinkHandler`),
 * `OidcAccountResolver` and `PasswordHasher`. Each one is optional: without
 * it, Better Auth keeps what its own config says.
 *
 * Handlers are found by class (`instanceof`), or in `AuthenticationRegistry`
 * when registered there, so none of Nest's own stores or module options are
 * needed for them: Better Auth keeps owning the tokens and the links.
 */
@Injectable()
export class BetterAuthHandlersWiring implements OnModuleInit, OnModuleDestroy {
	private readonly logger = new Logger("BetterAuthModule");
	/** The callbacks a handler replaced, put back when the app closes. */
	private readonly replaced: Array<[Options, string, unknown]> = [];

	constructor(
		@Inject(BETTER_AUTH_MODULE_OPTIONS)
		private readonly options: BetterAuthModuleOptions,
		@Inject(DiscoveryService) private readonly discovery: DiscoveryService,
		@Inject(AuthenticationRegistry)
		private readonly registry: AuthenticationRegistry,
		@Optional()
		@Inject(PasswordHasher)
		private readonly hasher?: PasswordHasher,
	) {}

	onModuleInit(): void {
		this.wirePasswordReset();
		this.wireEmailVerification();
		this.wireMagicLink();
		this.wireOidc();
		this.bindPasswordHasher();
	}

	onModuleDestroy(): void {
		for (const [parent, key, original] of this.replaced.splice(0).reverse()) {
			parent[key] = original;
		}
	}

	/** `PasswordResetHandler.send()` delivers Better Auth's reset links. */
	private wirePasswordReset(): void {
		const handler =
			this.find(PasswordResetHandler) ?? this.registry.handler("passwordReset");
		if (!handler) return;

		const parent = this.section(
			"emailAndPassword",
			"PasswordResetHandler",
			"emailAndPassword: { enabled: true }",
		);
		this.replace(parent, "emailAndPassword", "sendResetPassword", (async ({
			user,
			url,
		}: Options) =>
			handler.send({
				userId: user.id,
				email: user.email,
				url,
				expiresAt: expiresIn(parent.resetPasswordTokenExpiresIn ?? 3600),
			})) as never);
	}

	/** `EmailVerificationHandler.send()` delivers Better Auth's verification links. */
	private wireEmailVerification(): void {
		const handler =
			this.find(EmailVerificationHandler) ??
			this.registry.handler("emailVerification");
		if (!handler) return;

		const parent = this.section(
			"emailVerification",
			"EmailVerificationHandler",
			"emailVerification: {}",
		);
		this.replace(parent, "emailVerification", "sendVerificationEmail", (async ({
			user,
			url,
		}: Options) =>
			handler.send({
				userId: user.id,
				email: user.email,
				url,
				expiresAt: expiresIn(parent.expiresIn ?? 3600),
			})) as never);
	}

	/** `MagicLinkHandler.send()` delivers the `magicLink()` plugin's links. */
	private wireMagicLink(): void {
		const plugin = findPlugin(this.options.auth, "magic-link");
		const options = plugin?.options as Options | undefined;
		const handler =
			this.find(MagicLinkHandler) ?? this.registry.handler("magicLink");

		if (!handler) {
			if (options?.sendMagicLink?.[PLACEHOLDER])
				throw new Error(
					"magicLink({ sendMagicLink: fromNestHandler }) needs a MagicLinkHandler: provide a class extending it in one of your modules.",
				);
			return;
		}
		if (!options)
			throw new Error(
				"Found a MagicLinkHandler but Better Auth's magicLink() plugin is not configured. Add magicLink({ sendMagicLink: fromNestHandler }) to its plugins.",
			);

		this.replace(options, "magicLink", "sendMagicLink", (async ({
			email,
			url,
		}: Options) =>
			handler.send({
				email,
				url,
				expiresAt: expiresIn(options.expiresIn ?? 300),
			})) as never);
	}

	/**
	 * `OidcAccountResolver` decides which local user a social or OAuth
	 * identity belongs to, or refuses the link, before Better Auth stores it.
	 */
	private wireOidc(): void {
		const resolver =
			this.find(OidcAccountResolver) ?? this.registry.handler("oidc");
		if (!resolver) return;

		addDatabaseHook(
			bridgeOf(this.options.auth),
			"account",
			"create",
			"before",
			async (account, ctx) => {
				if (account.providerId === "credential") return;

				// `ctx` is absent when the account is created outside an endpoint.
				const context = ctx?.context ?? (await this.options.auth.$context);
				const user = await context.internalAdapter.findUserById(account.userId);
				const resolved = await resolver.resolveUser(
					{
						provider: account.providerId,
						subject: account.accountId,
						email: user?.email,
						emailVerified: !!user?.emailVerified,
						claims: {},
					},
					{
						accessToken: account.accessToken ?? "",
						refreshToken: account.refreshToken ?? undefined,
						idToken: account.idToken ?? undefined,
					},
					{
						linkTo: context.session
							? { id: context.session.user.id }
							: undefined,
					},
				);
				// Refuse the link. Throwing, not returning `false`: Better Auth
				// would still create a new user and sign them in, without the account.
				if (!resolved || resolved.id !== account.userId)
					throw new APIError("FORBIDDEN", {
						code: "ACCOUNT_LINK_REFUSED",
						message: "This account can't be linked.",
					});
			},
		);
	}

	/** Binds a `nestPasswordHasher()` placeholder to Nest's `PasswordHasher`. */
	private bindPasswordHasher(): void {
		const password = this.options.auth.options.emailAndPassword?.password as
			| BetterAuthPassword
			| undefined;
		const bind = password?.[BIND_PASSWORD_HASHER];
		if (!bind) return;
		if (!this.hasher)
			throw new Error(
				"nestPasswordHasher() needs Nest's PasswordHasher: import AuthenticationModule from '@nestjs/authentication'.",
			);
		bind(this.hasher);
	}

	private find<T>(type: abstract new (...args: never[]) => T): T | undefined {
		for (const { instance } of this.discovery.getProviders()) {
			if (instance instanceof type) return instance as T;
		}
		return undefined;
	}

	/** The `auth.options[key]` object a handler plugs into; it must be configured. */
	private section(key: string, handler: string, example: string): Options {
		const parent = this.options.auth.options[key];
		if (typeof parent !== "object" || parent === null)
			throw new Error(
				`Found a ${handler} but Better Auth's '${key}' is not configured. Add '${example}' to your betterAuth(...) options.`,
			);
		return parent;
	}

	/**
	 * Replaces a Better Auth callback with a Nest handler, saying so when it
	 * overrides one the config defines. Callbacks are replaced, not chained:
	 * chaining would send two emails.
	 */
	private replace(
		parent: Options,
		path: string,
		key: string,
		callback: (...args: never[]) => unknown,
	): void {
		if (typeof parent[key] === "function" && !parent[key][PLACEHOLDER]) {
			this.logger.log(`A Nest handler replaces the '${path}.${key}' callback.`);
		}
		this.replaced.push([parent, key, parent[key]]);
		parent[key] = callback;
	}
}
