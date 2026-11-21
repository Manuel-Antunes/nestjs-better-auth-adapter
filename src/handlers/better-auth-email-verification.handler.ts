import type { OnModuleDestroy, OnModuleInit } from "@nestjs/common";
import {
	type AuthenticationRegistry,
	EmailVerificationHandler,
} from "@nestjs/authentication";
import { authenticationOptionsOf } from "../better-auth.service.ts";
import type { AnyBetterAuthService } from "../interfaces/better-auth-service.interface.ts";
import type { BetterAuthEmailVerificationLink } from "../interfaces/handler-links.interface.ts";
import type { ConfigObject } from "../interfaces/handlers.interface.ts";
import {
	configSection,
	expiresIn,
	replaceCallback,
} from "./better-auth-config.ts";
import { featureOptions, pageLink } from "./links.ts";
import { OwnedByBetterAuthError } from "../errors/owned-by-better-auth.error.ts";

/**
 * An `EmailVerificationHandler` for Better Auth's email verification:
 * extend it, implement `send()`, and register it from your constructor
 * (`registry.registerHandler("emailVerification", this)`). Once registered,
 * it plugs itself into Better Auth's `emailVerification.sendVerificationEmail`
 * at startup, which then sends through the handler the registry holds: a
 * link to the `emailVerification.url` of the `AuthenticationModule`
 * options, `?token=…`, with the query Better Auth put on its own
 * (`callbackURL`). `url` is either Better Auth's own endpoint
 * (`https://example.com/api/auth/verify-email`), for the link Better Auth
 * would have sent, or a page of the app that hands the token to it
 * (`GET /verify-email?token=…`).
 *
 * `send()` gets what Better Auth gave its `sendVerificationEmail` callback,
 * on the link: the whole `user`, the `token` and the `request`.
 *
 * `isVerified()` keeps Nest's default (`user.emailVerified === true`, Better
 * Auth's field): `@Authenticate({ verifiedEmail: true })` asks it. Better
 * Auth marks addresses verified, so `markVerified()` throws.
 */
export abstract class BetterAuthEmailVerificationHandler
	extends EmailVerificationHandler
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
		if (this.#registry.handler("emailVerification") !== this) return;
		const { url: page } = featureOptions(
			authenticationOptionsOf(this.#betterAuth),
			"emailVerification",
		);
		const parent = configSection(
			this.#betterAuth.instance.options as ConfigObject,
			"emailVerification",
			"emailVerification",
			"emailVerification: {}",
		);
		this.#restore = replaceCallback(
			parent,
			"emailVerification.sendVerificationEmail",
			(async ({ user, url, token }: ConfigObject, request?: Request) =>
				// BetterAuthHandlersCheck refuses any other registered handler.
				(
					this.#registry.handler("emailVerification") as
						| BetterAuthEmailVerificationHandler
						| undefined
				)?.send({
					userId: user.id,
					email: user.email,
					url: pageLink(page, token, url),
					expiresAt: expiresIn(parent.expiresIn ?? 3600),
					user,
					token,
					request,
				})) as never,
		);
	}

	/** Sends `link` to `link.email`, with what Better Auth gave its callback. */
	abstract override send(
		link: BetterAuthEmailVerificationLink,
	): void | Promise<void>;

	/** Puts Better Auth's own callback back. */
	onModuleDestroy(): void {
		this.#restore?.();
		this.#restore = undefined;
	}

	markVerified(): never {
		throw OwnedByBetterAuthError.handlerStep(
			"markVerified",
			"Better Auth marks the address verified (GET /verify-email)",
		);
	}
}
