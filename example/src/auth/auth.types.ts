import type {
	BetterAuthAuthenticationTypes,
	BetterAuthSession,
} from "nestjs-better-auth-adapter";
import type { Auth } from "./create-auth.ts";

/**
 * Types `@CurrentUser()`, `@CurrentSession()` and `AuthenticationContext`
 * with this app's Better Auth instance: `user.role` (admin plugin),
 * `user.locale` (additional field), `session.activeOrganizationId`
 * (organization plugin), `session.mfaVerifiedAt` (nestjs plugin)…
 */
declare module "@nestjs/authentication" {
	interface AuthenticationTypes extends BetterAuthAuthenticationTypes<Auth> {}
}

export type User = Auth["$Infer"]["Session"]["user"];
/**
 * `mfaVerifiedAt` is added by the nestjs() plugin's schema but not inferred
 * by Better Auth's `$Infer`, so it is taken from `BetterAuthSession`.
 */
export type Session = Auth["$Infer"]["Session"]["session"] &
	Pick<BetterAuthSession, "mfaVerifiedAt">;
