import type { AccessControl, Role } from "better-auth/plugins/access";

/** Resource → actions, as Better Auth's statements list them. */
export type StatementsMap = Record<string, readonly string[]>;

export type AccessControlScope = "user" | "organization";

/** What `BetterAuthACPolicy()` / `BetterAuthOrganizationACPolicy()` attach to a class. */
export interface BetterAuthACPolicyMetadata {
	scope: AccessControlScope;
	resource: string;
	actions: readonly string[];
	statements: Record<string, readonly string[] | undefined>;
	wildcard?: string;
}

/**
 * What `admin()` and `organization()` take, typed as Better Auth's own
 * `AccessControl` and `Role`: the types the plugins' options declare, so
 * `admin(accessControl.admin())` compiles from the published declarations.
 */
export interface BetterAuthAccessControlOptions {
	ac: AccessControl;
	roles: Record<string, Role>;
}

export interface BuildAccessControlOptions {
	/**
	 * Keep Better Auth's own statements and roles (`user`, `session`, `member`,
	 * `invitation`…) so its built-in endpoints keep working. Better Auth's docs
	 * warn that custom roles otherwise override the defaults.
	 * @default true
	 */
	defaults?: boolean;
}

/** A plugin's default statements and roles. */
export type AccessControlDefaults = {
	statements: StatementsMap;
	roles: Record<string, StatementsMap>;
};
