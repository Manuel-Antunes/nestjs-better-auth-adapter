import type {
	EmailVerificationLink,
	MagicLink,
	PasswordResetLink,
} from "@nestjs/authentication";
import type { GenericEndpointContext } from "better-auth";
import type { BetterAuthUser } from "./better-auth-session.interface.ts";

/**
 * A password reset link, with what Better Auth gave its
 * `sendResetPassword` callback besides it.
 */
export interface BetterAuthPasswordResetLink extends PasswordResetLink {
	/** The user Better Auth found, with your additional fields: no lookup to address the mail by name. */
	user: BetterAuthUser;
	/**
	 * Better Auth's token, which `url` carries too. It resets the password
	 * while it's valid: to key records by it, store a hash of it.
	 */
	token: string;
	/** The request that asked for the link: none when the app called `auth.api` without one. */
	request?: Request;
}

/**
 * An email verification link, with what Better Auth gave its
 * `sendVerificationEmail` callback besides it.
 */
export interface BetterAuthEmailVerificationLink extends EmailVerificationLink {
	/** The user Better Auth is verifying, with your additional fields. */
	user: BetterAuthUser;
	/** Better Auth's token, which `url` carries too. */
	token: string;
	/** The request that asked for the link: none when the app called `auth.api` without one. */
	request?: Request;
}

/**
 * A magic link, with what the `magicLink()` plugin gave its `sendMagicLink`
 * callback besides it.
 */
export interface BetterAuthMagicLink extends MagicLink {
	/**
	 * Better Auth's token, which `url` carries too. It signs the user in
	 * while it's valid: to key records by it, store a hash of it.
	 */
	token: string;
	/** What the client passed to `signIn.magicLink({ metadata })`. */
	metadata?: Record<string, unknown>;
	/** The request that asked for the link: none when the app called `auth.api` without one. */
	request?: Request;
	/**
	 * The plugin's endpoint context, `sendMagicLink`'s second argument: the
	 * request's body, headers, and Better Auth's context (`context.context`).
	 */
	context?: GenericEndpointContext;
}
