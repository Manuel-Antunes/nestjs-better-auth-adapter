import type { OnModuleDestroy, OnModuleInit } from "@nestjs/common";
import {
	type AuthenticationRegistry,
	type OAuthTokens,
	OidcAccountResolver,
	type OidcProfile,
	type OidcResolveContext,
} from "@nestjs/authentication";
import { getOAuthState } from "better-auth/api";
import { authenticationOptionsOf } from "../better-auth.service.ts";
import { BetterAuthConfigAugmenter } from "../config/better-auth-config-augmenter.ts";
import type { AnyBetterAuthService } from "../interfaces/better-auth-service.interface.ts";
import { BetterAuthConfigurationError } from "../errors/better-auth-configuration.error.ts";
import type { BetterAuthUser } from "../interfaces/better-auth-session.interface.ts";
import type {
	ValidateUserInfoData,
	ValidateUserInfoResult,
} from "../interfaces/handlers.interface.ts";

/**
 * An `OidcAccountResolver` for Better Auth's social sign-ins: extend it and
 * register it from your constructor (`registry.registerHandler("oidc",
 * this)`). Once registered, it plugs itself into Better Auth's own gate,
 * `user.validateUserInfo` (after the config's one), at startup: before
 * Better Auth attaches a social or OAuth identity to an existing user, the
 * handler the registry holds confirms that user (returns it) or refuses
 * (`null`).
 *
 * Better Auth keeps finding the user: the provider account's owner, else
 * the address's, as `account.accountLinking` allows. A new identity creates
 * a new user, which Better Auth's sign-up options govern: the resolver isn't
 * asked. `context.linkTo` is set when a signed-in user connects a provider.
 *
 * Every method has a default, which confirms Better Auth's choice:
 * override {@link validate} to add the app's rules, {@link findUserId} or
 * {@link findUser} only to look users up somewhere else, and
 * {@link resolveUser} only to replace the whole flow.
 */
export abstract class BetterAuthOidcAccountResolver
	extends OidcAccountResolver
	implements OnModuleInit, OnModuleDestroy
{
	/** The `oidc` option keys that keep a meaning with Better Auth. */
	static readonly #MEANINGFUL = new Set(["callbackUrl", "providers"]);

	readonly #registry: AuthenticationRegistry;
	readonly #betterAuth: AnyBetterAuthService;
	/** Plugs the resolver into Better Auth's gate: built here, applied once registered. */
	readonly #config: BetterAuthConfigAugmenter;

	constructor(
		registry: AuthenticationRegistry,
		betterAuth: AnyBetterAuthService,
	) {
		super();
		this.#registry = registry;
		this.#betterAuth = betterAuth;
		// After the config's own gate, if any: `user` needn't be configured,
		// as validateUserInfo has no feature to turn on.
		this.#config = new BetterAuthConfigAugmenter(betterAuth.instance).wrap(
			"user.validateUserInfo",
			(original) => async (data, context) => {
				const result = await original?.(data, context);
				if (result?.error) return result;
				const resolver = registry.handler("oidc");
				return resolver ? this.#resolveIdentity(resolver, data) : undefined;
			},
			{ create: true },
		);
	}

	/** Plugs the registered resolver into Better Auth's gate, if it's this one. */
	async onModuleInit(): Promise<void> {
		if (this.#registry.handler("oidc") !== this) return;
		this.#checkOptions();
		await this.#config.apply();
	}

	/** Puts the config's own gate back. */
	onModuleDestroy(): void {
		this.#config.restore();
	}

	/**
	 * The user an identity belongs to, which confirms Better Auth's choice,
	 * or `null` to refuse it. By default the signed-in user connecting a
	 * provider (`context.linkTo`), else {@link findUserId}'s, loaded with
	 * {@link findUser}, then handed to {@link validate}. Override `validate()`
	 * to add the app's rules; this one only to replace the whole flow.
	 */
	resolveUser(
		profile: OidcProfile,
		_tokens: OAuthTokens,
		context: OidcResolveContext,
	): { id: string } | null | Promise<{ id: string } | null> {
		return this.#resolve(profile, context);
	}

	/**
	 * Confirms the user found for an identity (returns it), or refuses it
	 * (`null`, or a thrown error). By default, the user: Better Auth's own
	 * rules (`account.accountLinking`) already applied. Override it for the
	 * app's, as `validate()` on the credential providers.
	 */
	protected validate(
		user: BetterAuthUser,
		_profile: OidcProfile,
		_context: OidcResolveContext,
	): BetterAuthUser | null | Promise<BetterAuthUser | null> {
		return user;
	}

	/**
	 * Who Better Auth attaches the identity to: the provider account's
	 * owner, else the user with the profile's address. Override it to look
	 * the user up in a repository of your own.
	 */
	protected async findUserId(profile: OidcProfile): Promise<string | null> {
		const { internalAdapter } = await this.#betterAuth.instance.$context;
		const account = await internalAdapter.findAccountByKey({
			providerId: profile.provider,
			accountId: profile.subject,
		});
		if (account) return account.userId;
		if (!profile.email) return null;
		return (
			(await internalAdapter.findUserByEmail(profile.email))?.user.id ?? null
		);
	}

	/** The user of `id`, from Better Auth's database. Override it for a repository of your own. */
	protected async findUser(id: string): Promise<BetterAuthUser | null> {
		const { internalAdapter } = await this.#betterAuth.instance.$context;
		return (await internalAdapter.findUserById(id)) as BetterAuthUser | null;
	}

	/**
	 * Checks the `oidc` option of `AuthenticationModule` against Better
	 * Auth, which signs users in with its `socialProviders`: `callbackUrl`
	 * must be Better Auth's callback route (the redirect URI registered with
	 * each provider), `providers` a function (Nest's own OIDC client serves
	 * none), and the client's other options, which nothing reads, are refused.
	 */
	#checkOptions(): void {
		const oidc = authenticationOptionsOf(this.#betterAuth)?.oidc;
		const route = `${this.#betterAuth.basePath}/callback/:provider`;
		if (!oidc)
			throw new BetterAuthConfigurationError(
				`An oidc handler is registered but the AuthenticationModule \`oidc\` option is missing: set its \`callbackUrl\` to Better Auth's callback, like 'https://api.example.com${route}'.`,
			);
		if (
			typeof oidc.callbackUrl === "string" &&
			new URL(oidc.callbackUrl).pathname !== route
		)
			throw new BetterAuthConfigurationError(
				`AuthenticationModule's \`oidc.callbackUrl\` must be Better Auth's callback route, '${route}', which receives the providers' redirects: got '${oidc.callbackUrl}'.`,
			);
		if (typeof oidc.providers !== "function")
			throw new BetterAuthConfigurationError(
				"AuthenticationModule's `oidc.providers` would run Nest's own OIDC client next to Better Auth's socialProviders, which sign users in: pass `providers: () => null`.",
			);
		for (const key of Object.keys(oidc)) {
			if (
				!BetterAuthOidcAccountResolver.#MEANINGFUL.has(key) &&
				oidc[key as keyof typeof oidc] !== undefined
			)
				throw new BetterAuthConfigurationError(
					`AuthenticationModule's \`oidc.${key}\` has no effect with Better Auth, whose socialProviders sign users in: configure them in Better Auth.`,
				);
		}
	}

	/**
	 * Asks `resolver` (the one the registry holds) about an identity Better
	 * Auth is about to attach to an existing user: signing in with a linked
	 * provider, linking one by email, or a signed-in user connecting one
	 * (`linkTo`). The resolver returns that user to confirm Better Auth's
	 * choice, anything else refuses it. A new identity creates a new user,
	 * which Better Auth's sign-up options govern (`disableImplicitSignUp`,
	 * `disableSignUp`): the resolver isn't asked.
	 */
	async #resolveIdentity(
		resolver: OidcAccountResolver,
		{ user, source }: ValidateUserInfoData,
	): Promise<ValidateUserInfoResult> {
		const provider = source.oauth ?? source.sso;
		if (!provider || source.action === "create-user" || !user.id) return;

		const claims = provider.profile ?? {};
		const state = await getOAuthState().catch(() => null);
		const profile: OidcProfile = {
			provider: provider.providerId,
			subject: String(claims.sub ?? claims.id ?? ""),
			email: user.email,
			emailVerified: user.emailVerified === true,
			name: typeof user.name === "string" ? user.name : undefined,
			picture: typeof user.image === "string" ? user.image : undefined,
			claims,
		};
		const resolved = await resolver.resolveUser(
			profile,
			// Better Auth's gate runs before it stores the provider's tokens.
			{ accessToken: "" },
			{ linkTo: state?.link ? { id: state.link.userId } : undefined },
		);
		if (resolved?.id === user.id) return;
		return {
			error: "account_link_refused",
			errorDescription: "This account can't be linked.",
		};
	}

	async #resolve(
		profile: OidcProfile,
		context: OidcResolveContext,
	): Promise<{ id: string } | null> {
		const userId = context.linkTo?.id ?? (await this.findUserId(profile));
		const user = userId ? await this.findUser(userId) : null;
		return user ? this.validate(user, profile, context) : null;
	}
}
