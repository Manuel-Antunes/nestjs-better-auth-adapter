export const HOOK_KEY = Symbol.for("nestjs-better-auth-adapter:hook");
export const BEFORE_HOOK_KEY = Symbol.for(
	"nestjs-better-auth-adapter:before-hook",
);
export const AFTER_HOOK_KEY = Symbol.for(
	"nestjs-better-auth-adapter:after-hook",
);

export const DATABASE_HOOK_KEY = Symbol.for(
	"nestjs-better-auth-adapter:database-hook",
);
export const BEFORE_DATABASE_HOOK_KEY = Symbol.for(
	"nestjs-better-auth-adapter:before-database-hook",
);
export const AFTER_DATABASE_HOOK_KEY = Symbol.for(
	"nestjs-better-auth-adapter:after-database-hook",
);

/** Set by `BetterAuthACPolicy()` / `BetterAuthOrganizationACPolicy()` on the classes they create. */
export const BETTER_AUTH_AC_POLICY = Symbol.for(
	"nestjs-better-auth-adapter:ac-policy",
);
