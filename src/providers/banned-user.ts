import { BetterAuthBannedUserError } from "../errors/better-auth-banned-user.error.ts";
import type { Auth } from "../interfaces/better-auth-module-options.interface.ts";
import type { BetterAuthUser } from "../interfaces/better-auth-session.interface.ts";
import { hasPlugin } from "../plugins.ts";

/**
 * Whether bans apply: the `admin()` plugin defines `banned` and `banExpires`
 * (required columns of its schema), and enforces them on sessions.
 */
export const checksBans = (auth: Auth): boolean => hasPlugin(auth, "admin");

/**
 * Throws `BetterAuthBannedUserError` for a user the `admin()` plugin banned,
 * as it does at sign-in: banned, and the ban has no `banExpires` or it is
 * still ahead.
 */
export function assertNotBanned(user: BetterAuthUser): void {
	if (user.banned !== true) return;
	const expires = user.banExpires ? new Date(user.banExpires).getTime() : NaN;
	if (Number.isFinite(expires) && expires <= Date.now()) return;
	throw new BetterAuthBannedUserError();
}
