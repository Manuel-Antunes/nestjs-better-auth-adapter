import type { OnModuleDestroy, OnModuleInit } from "@nestjs/common";
import {
	type AuthenticationRegistry,
	EmailVerificationHandler,
} from "@nestjs/authentication";
import { authenticationOptionsOf } from "../better-auth.service.ts";
import { BetterAuthConfigAugmenter } from "../config/better-auth-config-augmenter.ts";
import type { AnyBetterAuthService } from "../interfaces/better-auth-service.interface.ts";
import type { BetterAuthEmailVerificationLink } from "../interfaces/handler-links.interface.ts";
import type { BetterAuthUser } from "../interfaces/better-auth-session.interface.ts";
import { expiresIn, featureOptions, pageLink } from "./links.ts";
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
			"emailVerification.sendVerificationEmail",
			async ({ user, url, token }, request) => {
				// BetterAuthHandlersCheck refuses any other registered handler.
				const handler = registry.handler("emailVerification") as
					| BetterAuthEmailVerificationHandler
					| undefined;
				await handler?.send({
					userId: user.id,
					email: user.email,
					url: pageLink(this.#page, token, url),
					expiresAt: expiresIn(
						auth.options.emailVerification?.expiresIn ?? 3600,
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
		if (this.#registry.handler("emailVerification") !== this) return;
		this.#page = featureOptions(
			authenticationOptionsOf(this.#betterAuth),
			"emailVerification",
		).url;
		await this.#config.apply();
	}

	/** Sends `link` to `link.email`, with what Better Auth gave its callback. */
	abstract override send(
		link: BetterAuthEmailVerificationLink,
	): void | Promise<void>;

	/** Puts Better Auth's own callback back. */
	onModuleDestroy(): void {
		this.#config.restore();
	}

	markVerified(): never {
		throw OwnedByBetterAuthError.handlerStep(
			"markVerified",
			"Better Auth marks the address verified (GET /verify-email)",
		);
	}
}
