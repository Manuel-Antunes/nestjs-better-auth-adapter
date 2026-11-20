import { Injectable } from "@nestjs/common";
import { AuthenticationRegistry, type MagicLink } from "@nestjs/authentication";
import {
	BetterAuthMagicLinkHandler,
	BetterAuthService,
} from "nestjs-better-auth-adapter";
import { InjectEnv } from "../../config/config.module.ts";
import type { Env } from "../../config/env.ts";
import { Mailer } from "../../mail/mailer.ts";
import { templates } from "../../mail/templates.ts";

/**
 * Delivers the links of Better Auth's `magicLink()` plugin. Registered as
 * the `magicLink` handler of AuthenticationRegistry, it receives a link to
 * the frontend's page (`magicLink.url`), which hands the token to Better
 * Auth's `/magic-link/verify` to sign in.
 */
@Injectable()
export class MagicLinkMailer extends BetterAuthMagicLinkHandler {
	constructor(
		registry: AuthenticationRegistry,
		betterAuth: BetterAuthService,
		private readonly mailer: Mailer,
		@InjectEnv() private readonly env: Env,
	) {
		// The base class plugs the registered handler into Better Auth at startup.
		super(registry, betterAuth);
		// From the constructor: the registry locks once the app has initialized.
		registry.registerHandler("magicLink", this);
	}

	async send({ email, url, expiresAt }: MagicLink) {
		await this.mailer.send({
			to: email,
			...templates.magicLink(this.env.APP_NAME, url, expiresAt),
		});
	}
}
