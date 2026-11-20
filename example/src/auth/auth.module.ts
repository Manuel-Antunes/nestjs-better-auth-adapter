import { Module } from "@nestjs/common";
import { AuthenticationModule } from "@nestjs/authentication";
import { AuthorizationModule } from "@nestjs/authorization";
import { BetterAuthModule } from "nestjs-better-auth-adapter";
import { ENV } from "../config/config.module.ts";
import type { Env } from "../config/env.ts";
import { AuthConfig } from "./auth.config.ts";
import { AccountLinkingResolver } from "./handlers/account-linking.resolver.ts";
import { EmailVerificationMailer } from "./handlers/email-verification.mailer.ts";
import { MagicLinkMailer } from "./handlers/magic-link.mailer.ts";
import { PasswordResetMailer } from "./handlers/password-reset.mailer.ts";
import { AuthRequestHooks } from "./hooks/auth-request.hooks.ts";
import { ApiKeyAuth } from "./providers/api-key.auth.ts";
import { JwtAuth } from "./providers/jwt.auth.ts";
import { SessionAuth } from "./providers/session.auth.ts";
import { SessionDatabaseHooks } from "./hooks/session-database.hooks.ts";
import { SensitiveRoutesHooks } from "./hooks/sensitive-routes.hooks.ts";
import { UserDatabaseHooks } from "./hooks/user-database.hooks.ts";

/**
 * Authentication and authorization, wired once for the whole app:
 *
 * 1. `AuthenticationModule` (Nest's): the global guard, `@CurrentUser()`,
 *    `@Authenticate()`, `AuthenticationContext`, and `PasswordHasher`.
 * 2. `BetterAuthModule`: Better Auth's routes on /api/auth, and the handlers
 *    and hooks below plugged into Better Auth. Global: `BetterAuthService`
 *    everywhere. The session, JWT and API key providers below extend its
 *    base classes and register themselves in Nest's chain.
 * 3. `AuthorizationModule` (Nest's): the global guard behind `@Can()`. It
 *    denies every route without `@Can()`, `@Can.Anyone()` or `@Public()`.
 *    The abilities are the policies' (`@Policy()` classes in each feature
 *    module), whose roles `BetterAuthAccessControl` gives Better Auth.
 */
@Module({
	imports: [
		AuthenticationModule.forRootAsync({
			inject: [ENV],
			// Better Auth hashes with Nest's PasswordHasher (see createAuth): its cost is set here.
			useFactory: (env: Env) => ({
				password: { logN: env.PASSWORD_HASH_LOG_N },
				// The frontend's pages for Better Auth's links: the registered
				// handlers send these, with Better Auth's token. How long a link
				// lasts is Better Auth's config (see createAuth).
				passwordReset: { url: `${env.APP_URL}/reset-password` },
				emailVerification: { url: `${env.APP_URL}/verify-email` },
				magicLink: { url: `${env.APP_URL}/sign-in/magic-link` },
				// Social sign-in is Better Auth's (its socialProviders): Nest's OIDC
				// client serves no provider, and the callback is Better Auth's
				// route, the redirect URI registered with GitHub and Google.
				// AccountLinkingResolver confirms or refuses Better Auth's links.
				oidc: {
					callbackUrl: `${env.BETTER_AUTH_URL}/api/auth/callback/:provider`,
					providers: () => null,
				},
			}),
		}),
		BetterAuthModule.forRootAsync({ useClass: AuthConfig }),
		AuthorizationModule.forRoot(),
	],
	providers: [
		// The credential providers, in their order in AuthenticationRegistry.
		SessionAuth,
		JwtAuth,
		ApiKeyAuth,
		// Register themselves in AuthenticationRegistry, then plug themselves
		// into Better Auth's email callbacks, which send through the registry.
		PasswordResetMailer,
		EmailVerificationMailer,
		MagicLinkMailer,
		// Registers itself as the oidc handler and plugs itself into Better
		// Auth's validateUserInfo gate, asked before an identity is attached.
		AccountLinkingResolver,
		// @Hook() / @DatabaseHook() providers, run through the nestjs() plugin.
		AuthRequestHooks,
		// A second factor and a verified email on Better Auth's sensitive routes.
		SensitiveRoutesHooks,
		UserDatabaseHooks,
		SessionDatabaseHooks,
	],
})
export class AuthModule {}
