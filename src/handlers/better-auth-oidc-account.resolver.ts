import type { OnModuleDestroy, OnModuleInit } from "@nestjs/common";
import {
	type AuthenticationRegistry,
	type OAuthTokens,
	OidcAccountResolver,
	type OidcProfile,
	type OidcResolveContext,
} from "@nestjs/authentication";
import { authenticationOptionsOf } from "../better-auth.service.ts";
import type { AnyBetterAuthService } from "../interfaces/better-auth-service.interface.ts";
import type { BetterAuthUser } from "../interfaces/better-auth-session.interface.ts";
import type {
	ConfigObject,
	UserInfoGate,
} from "../interfaces/handlers.interface.ts";
import { checkOidcOptions, resolveIdentity } from "./oidc.ts";

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
	readonly #registry: AuthenticationRegistry;
	readonly #betterAuth: AnyBetterAuthService;
	#restore?: () => void;

	constructor(
		registry: AuthenticationRegistry,
		betterAuth: AnyBetterAuthService,
	) {
		super();
		this.#registry = registry;
		this.#betterAuth = betterAuth;
	}

	/** Plugs the registered resolver into Better Auth's gate, if it's this one. */
	async onModuleInit(): Promise<void> {
		if (this.#registry.handler("oidc") !== this) return;
		checkOidcOptions(
			authenticationOptionsOf(this.#betterAuth),
			this.#betterAuth.basePath,
		);

		// The resolved options, which Better Auth reads at each call: the
		// config's top level is copied when the instance is created.
		const { options } = (await this.#betterAuth.instance.$context) as {
			options: ConfigObject;
		};
		options.user ??= {};
		const user: ConfigObject = options.user;
		const original = user.validateUserInfo as UserInfoGate | undefined;
		user.validateUserInfo = (async (data: never, context: unknown) => {
			const result = await original?.(data, context);
			if (result?.error) return result;
			const resolver = this.#registry.handler("oidc");
			return resolver ? resolveIdentity(resolver, data) : undefined;
		}) as UserInfoGate;
		this.#restore = () => {
			user.validateUserInfo = original;
		};
	}

	/** Puts the config's own gate back. */
	onModuleDestroy(): void {
		this.#restore?.();
		this.#restore = undefined;
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

	async #resolve(
		profile: OidcProfile,
		context: OidcResolveContext,
	): Promise<{ id: string } | null> {
		const userId = context.linkTo?.id ?? (await this.findUserId(profile));
		const user = userId ? await this.findUser(userId) : null;
		return user ? this.validate(user, profile, context) : null;
	}
}
