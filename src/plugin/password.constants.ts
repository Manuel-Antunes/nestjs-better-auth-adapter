/**
 * @internal Set by the `nestjs()` plugin: stores `upgraded` in place of the
 * credential hash `outdated`, if it is still that one.
 */
export const UPGRADE_HASH = Symbol.for(
	"nestjs-better-auth-adapter:upgrade-hash",
);

/** @internal How `BetterAuthModule` binds a `nestPasswordHasher()` placeholder. */
export const BIND_PASSWORD_HASHER = Symbol.for(
	"nestjs-better-auth-adapter:bind-password-hasher",
);
