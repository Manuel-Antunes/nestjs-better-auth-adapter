import { Injectable } from "@nestjs/common";
import {
	AuthenticationRegistry,
	type PasswordResetLink,
} from "@nestjs/authentication";
import {
	BetterAuthPasswordResetHandler,
	BetterAuthService,
} from "nestjs-better-auth-adapter";
import { InjectEnv } from "../../config/config.module.ts";
import type { Env } from "../../config/env.ts";
import { Mailer } from "../../mail/mailer.ts";
import { templates } from "../../mail/templates.ts";

/**
 * Delivers Better Auth's password reset links. Registered as the
 * `passwordReset` handler of AuthenticationRegistry, it receives a link to
 * the frontend's reset page (`passwordReset.url` in the AuthenticationModule
 * options) carrying Better Auth's token; that page posts the token and the
 * new password to Better Auth's `/reset-password`.
 */
@Injectable()
export class PasswordResetMailer extends BetterAuthPasswordResetHandler {
	constructor(
		registry: AuthenticationRegistry,
		betterAuth: BetterAuthService,
		private readonly mailer: Mailer,
		@InjectEnv() private readonly env: Env,
	) {
		// The base class plugs the registered handler into Better Auth at startup.
		super(registry, betterAuth);
		// From the constructor: the registry locks once the app has initialized.
		registry.registerHandler("passwordReset", this);
	}

	async send({ email, url, expiresAt }: PasswordResetLink) {
		await this.mailer.send({
			to: email,
			...templates.resetPassword(this.env.APP_NAME, url, expiresAt),
		});
	}
}
