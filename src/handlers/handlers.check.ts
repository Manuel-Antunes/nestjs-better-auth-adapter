import {
	Inject,
	Injectable,
	type OnApplicationBootstrap,
} from "@nestjs/common";
import {
	type AuthenticationHandlerName,
	AuthenticationRegistry,
} from "@nestjs/authentication";
import { BetterAuthService } from "../better-auth.service.ts";
import { BetterAuthConfigurationError } from "../errors/better-auth-configuration.error.ts";
import { PLACEHOLDER } from "../plugin/placeholders.ts";
import { findPlugin } from "../plugins.ts";
import { BetterAuthEmailVerificationHandler } from "./better-auth-email-verification.handler.ts";
import { BetterAuthMagicLinkHandler } from "./better-auth-magic-link.handler.ts";
import { BetterAuthOidcAccountResolver } from "./better-auth-oidc-account.resolver.ts";
import { BetterAuthPasswordResetHandler } from "./better-auth-password-reset.handler.ts";

/** The base class a handler of each feature extends, to plug itself into Better Auth. */
const BASES: Record<
	AuthenticationHandlerName,
	abstract new (
		...args: never[]
	) => object
> = {
	passwordReset: BetterAuthPasswordResetHandler,
	emailVerification: BetterAuthEmailVerificationHandler,
	magicLink: BetterAuthMagicLinkHandler,
	oidc: BetterAuthOidcAccountResolver,
};

/**
 * Once every handler has plugged itself in (their `onModuleInit`): fails on
 * a registered handler that can't, as Better Auth would never call it, and
 * on a `fromNestHandler` placeholder that no handler replaced.
 */
@Injectable()
export class BetterAuthHandlersCheck implements OnApplicationBootstrap {
	constructor(
		@Inject(AuthenticationRegistry)
		private readonly registry: AuthenticationRegistry,
		@Inject(BetterAuthService) private readonly betterAuth: BetterAuthService,
	) {}

	onApplicationBootstrap(): void {
		for (const [feature, base] of Object.entries(BASES)) {
			const handler = this.registry.handler(
				feature as AuthenticationHandlerName,
			);
			if (handler && !(handler instanceof base))
				throw new BetterAuthConfigurationError(
					`${handler.constructor.name} is registered as the ${feature} handler, but Better Auth runs ${feature} here: extend ${base.name}, which plugs it into Better Auth.`,
				);
		}

		const magicLink = findPlugin(this.betterAuth.instance, "magic-link")
			?.options as { sendMagicLink?: { [PLACEHOLDER]?: true } } | undefined;
		if (magicLink?.sendMagicLink?.[PLACEHOLDER])
			throw new BetterAuthConfigurationError(
				"magicLink({ sendMagicLink: fromNestHandler }) needs a magicLink handler: a class extending BetterAuthMagicLinkHandler that registers itself (registry.registerHandler('magicLink', this)), with `magicLink: { url }` in the AuthenticationModule options.",
			);
	}
}
