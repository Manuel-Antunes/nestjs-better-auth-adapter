import type { AuthHookContext } from "./bridge.interface.ts";

export interface NestjsPluginOptions {
	/**
	 * Record on each session whether its second factor was verified
	 * (`session.mfaVerifiedAt`), which `@Authenticate({ mfa: true })` reads.
	 * Adds a column to the session table.
	 * @default true
	 */
	mfa?: boolean;
}

/** What the `nestjs()` plugin reads of `twoFactor()`. */
export type TwoFactorPlugin = {
	shouldRequireTwoFactor?: (ctx: AuthHookContext) => Promise<boolean>;
};
