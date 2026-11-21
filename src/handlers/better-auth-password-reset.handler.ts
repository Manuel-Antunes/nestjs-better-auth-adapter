import type { OnModuleDestroy, OnModuleInit } from "@nestjs/common";
import {
	type AuthenticationRegistry,
	PasswordResetHandler,
} from "@nestjs/authentication";
import { authenticationOptionsOf } from "../better-auth.service.ts";
import { BetterAuthConfigAugmenter } from "../config/better-auth-config-augmenter.ts";
import type { AnyBetterAuthService } from "../interfaces/better-auth-service.interface.ts";
import type { BetterAuthUser } from "../interfaces/better-auth-session.interface.ts";
import type { BetterAuthPasswordResetLink } from "../interfaces/handler-links.interface.ts";
import { expiresIn, featureOptions, pageLink } from "./links.ts";
import { OwnedByBetterAuthError } from "../errors/owned-by-better-auth.error.ts";

/**
 * A `PasswordResetHandler` for Better Auth's password resets: extend it,
 * implement `send()`, and register it from your constructor, as any Nest
 * handler. Once registered as `passwordReset`, it plugs itself into Better
 * Auth's `emailAndPassword.sendResetPassword` at startup, which then sends
 * through the handler the registry holds: a link to the `passwordReset.url`
 * page of the `AuthenticationModule` options, `?token=…`, with the query
 * Better Auth put on its own (`callbackURL`). That page posts the token and
 * the new password to Better Auth (`POST /reset-password`): unlike the
 * other links, Better Auth's own has the token in its path
 * (`/reset-password/:token`), which `?token=` can't reproduce.
 *
 * `send()` gets what Better Auth gave its `sendResetPassword` callback, on
 * the link: the whole `user` (to address the mail by name without a
 * lookup), the `token` and the `request`.
 *
 * Better Auth finds the account and stores the new password: the rest of
 * Nest's contract (`findUser()`, `updatePassword()`) throws.
 *
 * @example
 * ```ts
 * @Injectable()
 * export class ResetMailer extends BetterAuthPasswordResetHandler {
 *   constructor(registry: AuthenticationRegistry, betterAuth: BetterAuthService, private readonly mailer: Mailer) {
 *     super(registry, betterAuth);
 *     registry.registerHandler("passwordReset", this);
 *   }
 *
 *   send({ email, url }: BetterAuthPasswordResetLink) {
 *     return this.mailer.send(email, "Reset your password", url);
 *   }
 * }
 * ```
 */
export abstract class BetterAuthPasswordResetHandler
	extends PasswordResetHandler
	implements OnModuleInit, OnModuleDestroy
{
	readonly #registry: AuthenticationRegistry;
	readonly #betterAuth: AnyBetterAuthService;
	/** Plugs `send()` into Better Auth: built here, applied once registered. */
	readonly #config: BetterAuthConfigAugmenter;
	/** The feature's `url` in the `AuthenticationModule` options, read once registered. */
	#page = "";

	constructor(
		registry: AuthenticationRegistry,
		betterAuth: AnyBetterAuthService,
	) {
		super();
		this.#registry = registry;
		this.#betterAuth = betterAuth;
		const auth = betterAuth.instance;
		this.#config = new BetterAuthConfigAugmenter(auth).replace(
			"emailAndPassword.sendResetPassword",
			async ({ user, url, token }, request) => {
				// BetterAuthHandlersCheck refuses any other registered handler.
				const handler = registry.handler("passwordReset") as
					| BetterAuthPasswordResetHandler
					| undefined;
				await handler?.send({
					userId: user.id,
					email: user.email,
					url: pageLink(this.#page, token, url),
					expiresAt: expiresIn(
						auth.options.emailAndPassword?.resetPasswordTokenExpiresIn ?? 3600,
					),
					user: user as BetterAuthUser,
					token,
					request,
				});
			},
		);
	}

	/** Plugs the registered handler into Better Auth, if it's this one. */
	async onModuleInit(): Promise<void> {
		if (this.#registry.handler("passwordReset") !== this) return;
		this.#page = featureOptions(
			authenticationOptionsOf(this.#betterAuth),
			"passwordReset",
		).url;
		await this.#config.apply();
	}

	/** Sends `link` to `link.email`, with what Better Auth gave its callback. */
	abstract override send(
		link: BetterAuthPasswordResetLink,
	): void | Promise<void>;

	/** Puts Better Auth's own callback back. */
	onModuleDestroy(): void {
		this.#config.restore();
	}

	findUser(): never {
		throw OwnedByBetterAuthError.handlerStep(
			"findUser",
			"Better Auth finds the account (POST /request-password-reset)",
		);
	}

	updatePassword(): never {
		throw OwnedByBetterAuthError.handlerStep(
			"updatePassword",
			"Better Auth stores the new password (POST /reset-password)",
		);
	}
}
