import { Inject, Logger, Module } from "@nestjs/common";
import { Policy } from "@nestjs/authorization";
import { BetterAuthService } from "../better-auth.service.ts";
import type { BetterAuthUser } from "../types.ts";
import {
	findMember,
	matchesRequiredRole,
	memberHasPermission,
} from "./organization.ts";

/** Resource → actions, as Better Auth's access control checks them. */
export type PermissionCheck = Record<string, string[]>;

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
 * Provided by {@link BetterAuthAuthorizationModule}.
 */
@Policy()
export class BetterAuthPermissionPolicy {
	private readonly logger = new Logger(BetterAuthPermissionPolicy.name);

	constructor(
		@Inject(BetterAuthService) private readonly betterAuth: BetterAuthService,
	) {}

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
		const member = await findMember(this.betterAuth, user.id, organizationId);
		return matchesRequiredRole(member?.role, roles);
	}

	/**
	 * The user's role grants `permissions`, through the `admin()` plugin's
	 * access control. `role` checks a role instead of the user's.
	 */
	async userHasPermission(
		user: BetterAuthUser | null,
		permissions: PermissionCheck,
		role?: string,
	): Promise<boolean> {
		if (!user) return false;
		try {
			// biome-ignore lint/suspicious/noExplicitAny: the API only exists with the admin plugin
			const api = this.betterAuth.api as any;
			const result = await api.userHasPermission({
				body: role ? { role, permissions } : { userId: user.id, permissions },
			});
			return result?.success === true;
		} catch (error) {
			this.logger.error("userHasPermission failed", error);
			return false;
		}
	}

	/** The user's member role grants `permissions` in the organization. */
	async memberHasPermission(
		user: BetterAuthUser | null,
		organizationId: string | null | undefined,
		permissions: PermissionCheck,
	): Promise<boolean> {
		if (!user || !organizationId) return false;
		try {
			return await memberHasPermission(
				this.betterAuth,
				user.id,
				organizationId,
				permissions,
			);
		} catch (error) {
			this.logger.error("memberHasPermission failed", error);
			return false;
		}
	}
}

/** Provides {@link BetterAuthPermissionPolicy}. */
@Module({
	providers: [BetterAuthPermissionPolicy],
	exports: [BetterAuthPermissionPolicy],
})
export class BetterAuthAuthorizationModule {}
