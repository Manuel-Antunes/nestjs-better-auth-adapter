import type { OnModuleDestroy, OnModuleInit } from "@nestjs/common";
import {
	type AuthenticationRegistry,
	MagicLinkHandler,
} from "@nestjs/authentication";
import { authenticationOptionsOf } from "../better-auth.service.ts";
import type { AnyBetterAuthService } from "../interfaces/better-auth-service.interface.ts";
import { BetterAuthConfigurationError } from "../errors/better-auth-configuration.error.ts";
import { findPlugin } from "../plugins.ts";
import type { ConfigObject } from "../interfaces/handlers.interface.ts";
import { expiresIn, replaceCallback } from "./better-auth-config.ts";
import { featureOptions, pageLink } from "./links.ts";
import { OwnedByBetterAuthError } from "../errors/owned-by-better-auth.error.ts";

/**
 * A `MagicLinkHandler` for the links of Better Auth's `magicLink()` plugin:
 * extend it, implement `send()`, and register it from your constructor
 * (`registry.registerHandler("magicLink", this)`). Once registered, it plugs
 * itself into `magicLink({ sendMagicLink: fromNestHandler })` at startup,
 * which then sends through the handler the registry holds: a link to the
 * `magicLink.url` page of the `AuthenticationModule` options, `?token=…`.
 * That page hands the token to Better Auth (`GET /magic-link/verify?token=…`),
 * which signs the user in.
 *
 * Better Auth maps the address to a user (`magicLink({ disableSignUp })`),
 * so `resolveUser()` throws.
 */
export abstract class BetterAuthMagicLinkHandler
	extends MagicLinkHandler
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
		if (this.#registry.handler("magicLink") !== this) return;
		const options = findPlugin(this.#betterAuth.instance, "magic-link")
			?.options as ConfigObject | undefined;
		if (!options)
			throw new BetterAuthConfigurationError(
				"A magicLink handler is registered but Better Auth's magicLink() plugin is not configured. Add magicLink({ sendMagicLink: fromNestHandler }) to its plugins.",
			);
		const { url: page } = featureOptions(
			authenticationOptionsOf(this.#betterAuth),
			"magicLink",
		);
		this.#restore = replaceCallback(
			options,
			"magicLink.sendMagicLink",
			(async ({ email, url, token }: ConfigObject) =>
				this.#registry.handler("magicLink")?.send({
					email,
					url: pageLink(page, token, url),
					expiresAt: expiresIn(options.expiresIn ?? 300),
				})) as never,
		);
	}

	/** Puts the plugin's own callback back. */
	onModuleDestroy(): void {
		this.#restore?.();
		this.#restore = undefined;
	}

	resolveUser(): never {
		throw OwnedByBetterAuthError.handlerStep(
			"resolveUser",
			"Better Auth maps the address to a user (GET /magic-link/verify)",
		);
	}
}
