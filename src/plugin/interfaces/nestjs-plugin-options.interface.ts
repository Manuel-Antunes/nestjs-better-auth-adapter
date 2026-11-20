import type { AuthHookContext } from "./bridge.interface.ts";

export interface NestjsPluginOptions {
	/**
	 * Record on each session whether its second factor was verified
	 * (`session.mfaVerifiedAt`), which `@Authenticate({ mfa: true })` reads.
	 * Adds a column to the session table.
	 * @default true
	 */
	mfa?: boolean;
	/**
	 * Publish Better Auth's sign-ins, sign-outs, second-factor changes,
	 * password resets and email verifications as `@nestjs/authentication`'s
	 * `AuthenticationEvents`, once `BetterAuthModule` runs next to
	 * `AuthenticationModule`.
	 * @default true
	 */
	events?: boolean;
}

/** What the `nestjs()` plugin reads of `twoFactor()`. */
export type TwoFactorPlugin = {
	shouldRequireTwoFactor?: (ctx: AuthHookContext) => Promise<boolean>;
};
