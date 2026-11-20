import { Injectable } from "@nestjs/common";
import {
	AuthenticationRegistry,
	type EmailVerificationLink,
} from "@nestjs/authentication";
import {
	BetterAuthEmailVerificationHandler,
	BetterAuthService,
} from "nestjs-better-auth-adapter";
import { InjectEnv } from "../../config/config.module.ts";
import type { Env } from "../../config/env.ts";
import { Mailer } from "../../mail/mailer.ts";
import { templates } from "../../mail/templates.ts";

/**
 * Delivers Better Auth's verification links. Registered as the
 * `emailVerification` handler of AuthenticationRegistry, it receives a link
 * to the frontend's page (`emailVerification.url`), which hands the token to
 * Better Auth's `/verify-email`. Its inherited `isVerified()` is what
 * `@Authenticate({ verifiedEmail: true })` asks: Better Auth's
 * `user.emailVerified`.
 */
@Injectable()
export class EmailVerificationMailer extends BetterAuthEmailVerificationHandler {
	constructor(
		registry: AuthenticationRegistry,
		betterAuth: BetterAuthService,
		private readonly mailer: Mailer,
		@InjectEnv() private readonly env: Env,
	) {
		// The base class plugs the registered handler into Better Auth at startup.
		super(registry, betterAuth);
		// From the constructor: the registry locks once the app has initialized.
		registry.registerHandler("emailVerification", this);
	}

	async send({ email, url, expiresAt }: EmailVerificationLink) {
		await this.mailer.send({
			to: email,
			...templates.verifyEmail(this.env.APP_NAME, url, expiresAt),
		});
	}
}
