import type { OnModuleDestroy, OnModuleInit } from "@nestjs/common";
import {
	type AuthenticationRegistry,
	MagicLinkHandler,
} from "@nestjs/authentication";
import type { GenericEndpointContext } from "better-auth";
import type { MagicLinkOptions } from "better-auth/plugins/magic-link";
import { authenticationOptionsOf } from "../better-auth.service.ts";
import { BetterAuthConfigAugmenter } from "../config/better-auth-config-augmenter.ts";
import type { AnyBetterAuthService } from "../interfaces/better-auth-service.interface.ts";
import { BetterAuthConfigurationError } from "../errors/better-auth-configuration.error.ts";
import { findPlugin, hasPlugin } from "../plugins.ts";
import type { BetterAuthMagicLink } from "../interfaces/handler-links.interface.ts";
import { expiresIn, featureOptions, pageLink } from "./links.ts";

/** The plugin's `sendMagicLink`, as `magicLink()` declares it. */
type SendMagicLink = MagicLinkOptions["sendMagicLink"];
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
		this.#config = new BetterAuthConfigAugmenter(betterAuth.instance).plugin(
			"magic-link",
			(magicLink) =>
				magicLink.replace(
					"sendMagicLink",
					async (
						{ email, url, token, metadata }: Parameters<SendMagicLink>[0],
						context?: GenericEndpointContext,
					) => {
						// BetterAuthHandlersCheck refuses any other registered handler.
						const handler = registry.handler("magicLink") as
							| BetterAuthMagicLinkHandler
							| undefined;
						await handler?.send({
							email,
							url: pageLink(this.#page, token, url),
							expiresAt: expiresIn(this.#expiresIn()),
							token,
							...(metadata !== undefined && { metadata }),
							request: context?.request,
							context,
						});
					},
				),
		);
	}

	/** Plugs the registered handler into Better Auth, if it's this one. */
	async onModuleInit(): Promise<void> {
		if (this.#registry.handler("magicLink") !== this) return;
		if (!hasPlugin(this.#betterAuth.instance, "magic-link"))
			throw new BetterAuthConfigurationError(
				"A magicLink handler is registered but Better Auth's magicLink() plugin is not configured. Add magicLink({ sendMagicLink: fromNestHandler }) to its plugins.",
			);
		this.#page = featureOptions(
			authenticationOptionsOf(this.#betterAuth),
			"magicLink",
		).url;
		await this.#config.apply();
	}

	/** How long the plugin's links last, in seconds: read at each link, as the plugin does. */
	#expiresIn(): number {
		const expires = findPlugin(this.#betterAuth.instance, "magic-link")?.options
			?.expiresIn;
		return typeof expires === "number" ? expires : 300;
	}

	/** Sends `link` to `link.email`, with what the plugin gave its callback. */
	abstract override send(link: BetterAuthMagicLink): void | Promise<void>;

	/** Puts the plugin's own callback back. */
	onModuleDestroy(): void {
		this.#config.restore();
	}

	resolveUser(): never {
		throw OwnedByBetterAuthError.handlerStep(
			"resolveUser",
			"Better Auth maps the address to a user (GET /magic-link/verify)",
		);
	}
}
