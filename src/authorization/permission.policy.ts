import { Logger } from "@nestjs/common";
import { Policy } from "@nestjs/authorization";
import type { BetterAuthUser } from "../interfaces/better-auth-session.interface.ts";
import { BetterAuthPolicy } from "./better-auth.policy.ts";
import type { PermissionCheck } from "./interfaces/permission-check.interface.ts";

/**
 * Whether a role value (a string, a comma-separated string or an array)
 * matches any of the required roles.
 */
function matchesRequiredRole(
	role: string | string[] | undefined | null,
	requiredRoles: readonly string[],
): boolean {
	if (!role) return false;
	const roles = Array.isArray(role) ? role : role.split(",");
	return roles.some((r) => requiredRoles.includes(r.trim()));
}

/**
 * Better Auth's role and permission checks as `@nestjs/authorization`
 * abilities, for routes that don't need a policy class of their own. The
 * arguments after the user come from `@Can()`'s resolver:
 *
 * @example
 * ```ts
 * @Can(BetterAuthPermissionPolicy, 'hasRole', () => [['admin']])
 * @Can(BetterAuthPermissionPolicy, 'userHasPermission', () => [{ project: ['create'] }])
 * @Can(BetterAuthPermissionPolicy, 'memberHasPermission', async (ctx) => [
 *   ...(await activeOrganization(ctx)),
 *   { project: ['create'] },
 * ])
 * ```
 *
 * Provided by `BetterAuthAuthorizationModule`.
 */
@Policy()
export class BetterAuthPermissionPolicy extends BetterAuthPolicy {
	private readonly logger = new Logger(BetterAuthPermissionPolicy.name);

	/** `user.role` (`admin()` plugin) is one of `roles`. */
	hasRole(user: BetterAuthUser | null, roles: readonly string[]): boolean {
		return !!user && matchesRequiredRole(user.role, roles);
	}

	/** The session has an active organization (`organization()` plugin). */
	hasActiveOrganization(
		user: BetterAuthUser | null,
		organizationId: string | null | undefined,
	): boolean {
		return !!user && !!organizationId;
	}

	/** The user's member role in the organization is one of `roles`. */
	async hasOrganizationRole(
		user: BetterAuthUser | null,
		organizationId: string | null | undefined,
		roles: readonly string[],
	): Promise<boolean> {
		if (!user || !organizationId) return false;
		const member = await this.findMember(user.id, organizationId);
		return matchesRequiredRole(member?.role, roles);
	}

	/**
	 * The user's role grants `permissions`, through the `admin()` plugin's
	 * access control. `role` checks a role instead of the user's.
	 */
	override async userHasPermission(
		user: BetterAuthUser | null,
		permissions: PermissionCheck,
		role?: string,
	): Promise<boolean> {
		if (!user) return false;
		try {
			return await super.userHasPermission(user, permissions, role);
		} catch (error) {
			this.logger.error("userHasPermission failed", error);
			return false;
		}
	}

	/** The user's member role grants `permissions` in the organization. */
	override async memberHasPermission(
		user: BetterAuthUser | null,
		organizationId: string | null | undefined,
		permissions: PermissionCheck,
	): Promise<boolean> {
		if (!user || !organizationId) return false;
		try {
			return await super.memberHasPermission(user, organizationId, permissions);
		} catch (error) {
			this.logger.error("memberHasPermission failed", error);
			return false;
		}
	}
}
