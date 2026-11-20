import type { OnModuleDestroy, OnModuleInit } from "@nestjs/common";
import {
	type AuthenticationRegistry,
	PasswordResetHandler,
} from "@nestjs/authentication";
import { authenticationOptionsOf } from "../better-auth.service.ts";
import type { AnyBetterAuthService } from "../interfaces/better-auth-service.interface.ts";
import type { ConfigObject } from "../interfaces/handlers.interface.ts";
import {
	configSection,
	expiresIn,
	replaceCallback,
} from "./better-auth-config.ts";
import { featureOptions, pageLink } from "./links.ts";
import { OwnedByBetterAuthError } from "../errors/owned-by-better-auth.error.ts";

/**
 * A `PasswordResetHandler` for Better Auth's password resets: extend it,
 * implement `send()`, and register it from your constructor, as any Nest
 * handler. Once registered as `passwordReset`, it plugs itself into Better
 * Auth's `emailAndPassword.sendResetPassword` at startup, which then sends
 * through the handler the registry holds: a link to the `passwordReset.url`
 * page of the `AuthenticationModule` options, `?token=…`. That page posts
 * the token and the new password to Better Auth (`POST /reset-password`).
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
 *   send({ email, url }: PasswordResetLink) {
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
	#restore?: () => void;

	constructor(
		registry: AuthenticationRegistry,
		betterAuth: AnyBetterAuthService,
	) {
		super();
		this.#registry = registry;
		this.#betterAuth = betterAuth;
	}

	/** Plugs the registered handler into Better Auth, if it's this one. */
	onModuleInit(): void {
		if (this.#registry.handler("passwordReset") !== this) return;
		const { url: page } = featureOptions(
			authenticationOptionsOf(this.#betterAuth),
			"passwordReset",
		);
		const parent = configSection(
			this.#betterAuth.instance.options as ConfigObject,
			"emailAndPassword",
			"passwordReset",
			"emailAndPassword: { enabled: true }",
		);
		this.#restore = replaceCallback(
			parent,
			"emailAndPassword.sendResetPassword",
			(async ({ user, url, token }: ConfigObject) =>
				this.#registry.handler("passwordReset")?.send({
					userId: user.id,
					email: user.email,
					url: pageLink(page, token, url),
					expiresAt: expiresIn(parent.resetPasswordTokenExpiresIn ?? 3600),
				})) as never,
		);
	}

	/** Puts Better Auth's own callback back. */
	onModuleDestroy(): void {
		this.#restore?.();
		this.#restore = undefined;
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
