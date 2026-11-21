import type { OnModuleDestroy, OnModuleInit } from "@nestjs/common";
import {
	type AuthenticationRegistry,
	MagicLinkHandler,
} from "@nestjs/authentication";
import type { GenericEndpointContext } from "better-auth";
import { authenticationOptionsOf } from "../better-auth.service.ts";
import type { AnyBetterAuthService } from "../interfaces/better-auth-service.interface.ts";
import { BetterAuthConfigurationError } from "../errors/better-auth-configuration.error.ts";
import { findPlugin } from "../plugins.ts";
import type { BetterAuthMagicLink } from "../interfaces/handler-links.interface.ts";
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
 * `magicLink.url` of the `AuthenticationModule` options, `?token=…`, with
 * the query Better Auth put on its own (`callbackURL`…). `url` is either
 * Better Auth's own endpoint (`https://example.com/api/auth/magic-link/verify`),
 * for the link Better Auth would have sent, or a page of the app that hands
 * the token to it (`GET /magic-link/verify?token=…`), which signs the user in.
 *
 * `send()` gets what the plugin gave its `sendMagicLink` callback, on the
 * link: the `token`, the client's `metadata` (`signIn.magicLink({ metadata })`),
 * the `request` and the plugin's endpoint `context`.
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
		this.#restore = replaceCallback(options, "magicLink.sendMagicLink", (async (
			{ email, url, token, metadata }: ConfigObject,
			context?: GenericEndpointContext,
		) =>
			// BetterAuthHandlersCheck refuses any other registered handler.
			(
				this.#registry.handler("magicLink") as
					| BetterAuthMagicLinkHandler
					| undefined
			)?.send({
				email,
				url: pageLink(page, token, url),
				expiresAt: expiresIn(options.expiresIn ?? 300),
				token,
				...(metadata !== undefined && { metadata }),
				request: context?.request,
				context,
			})) as never);
	}

	/** Sends `link` to `link.email`, with what the plugin gave its callback. */
	abstract override send(link: BetterAuthMagicLink): void | Promise<void>;

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
