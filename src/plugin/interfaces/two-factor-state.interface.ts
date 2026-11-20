/** What a `twoFactor()` request found before its endpoint ran. */
export interface TwoFactorState {
	/** The user verifying or enrolling: the session's, or the sign-in challenge's. */
	userId?: string;
	/** A sign-in challenge (no session yet), not a step-up. */
	signIn: boolean;
	/** `user.twoFactorEnabled`. */
	enabled: boolean;
	/** Whether the user's TOTP authenticator was confirmed. */
	confirmed: boolean;
	/** Whether a verification on this request counts as a second factor. */
	counts: boolean;
}
