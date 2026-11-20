import type { getSession } from "better-auth/api";

type ResolvedSession = NonNullable<
	Awaited<ReturnType<ReturnType<typeof getSession>>>
>;

/** The user Better Auth resolves for a request. */
export type BetterAuthUser = ResolvedSession["user"] & {
	/** Set by the `admin()` plugin. */
	role?: string | string[] | null;
	/** Set by the `admin()` plugin: the user is banned, until `banExpires` if set. */
	banned?: boolean | null;
	/** Set by the `admin()` plugin. */
	banExpires?: Date | string | null;
	/** Set by the `twoFactor()` plugin. */
	twoFactorEnabled?: boolean | null;
};

/** The session Better Auth resolves for a request. */
export type BetterAuthSession = ResolvedSession["session"] & {
	/** Set by the `organization()` plugin. */
	activeOrganizationId?: string | null;
	/** Set by this package's `nestjs()` Better Auth plugin when a second factor was verified on this session. */
	mfaVerifiedAt?: Date | null;
};

/**
 * Types `@CurrentUser()`, `@CurrentSession()` and `AuthenticationContext`
 * with your Better Auth instance, plugins and additional fields included.
 * Augment `@nestjs/authentication` once per app:
 *
 * @example
 * ```ts
 * declare module '@nestjs/authentication' {
 *   interface AuthenticationTypes extends BetterAuthAuthenticationTypes<typeof auth> {}
 * }
 * ```
 */
export type BetterAuthAuthenticationTypes<T> = T extends {
	$Infer: { Session: { user: infer U; session: infer S } };
}
	? { user: U; session: S }
	: { user: BetterAuthUser; session: BetterAuthSession };
