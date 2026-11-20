import { Inject } from "@nestjs/common";
import { getOrgAdapter, hasPermission } from "better-auth/plugins";
import { BetterAuthService } from "../better-auth.service.ts";
import { findPlugin } from "../plugins.ts";
import type { BetterAuthUser } from "../interfaces/better-auth-session.interface.ts";
import type { PermissionCheck } from "./interfaces/permission-check.interface.ts";

/**
 * Internal base of the AC policies and `BetterAuthPermissionPolicy`, not
 * exported: `BetterAuthService` and Better Auth's checks as protected
 * helpers, which the policies' abilities call. Being protected keeps the
 * helpers out of `@Can()`'s abilities (their names are reserved for AC
 * policy actions). They need no request, so they also work from
 * `AuthorizationService` in queue workers.
 */
export abstract class BetterAuthPolicy {
	// Property injection, like SessionCookieProvider's SessionService in
	// @nestjs/authentication: subclasses declare their own constructor
	// dependencies without forwarding this one.
	@Inject(BetterAuthService) readonly betterAuth!: BetterAuthService;

	/**
	 * Whether the user's role grants `permissions`, through the `admin()`
	 * plugin's access control. `role` checks a role instead of the user's.
	 * The role `user` carries is used as is (the guard's user was just read
	 * from the database), unless the session cookie cache is on: Better Auth
	 * then reads it again.
	 */
	protected async userHasPermission(
		user: BetterAuthUser,
		permissions: PermissionCheck,
		role?: string,
	): Promise<boolean> {
		// biome-ignore lint/suspicious/noExplicitAny: the API only exists with the admin plugin
		const api = this.betterAuth.api as any;
		const ownRole = role ? undefined : this.#currentRole(user);
		const result = await api.userHasPermission({
			body: role
				? { role, permissions }
				: // With the role at hand, Better Auth doesn't look the user up again.
					{ userId: user.id, ...(ownRole && { role: ownRole }), permissions },
		});
		return result?.success === true;
	}

	/**
	 * The user's role when it is current, else `undefined` (Better Auth then
	 * reads it from the database): a role from the cookie cache may predate
	 * a `setRole()`, so it is only trusted when the cache is off.
	 */
	#currentRole(user: BetterAuthUser): string | undefined {
		const role = Array.isArray(user.role) ? user.role.join(",") : user.role;
		if (!role) return undefined;
		const options = this.betterAuth.instance.options as {
			session?: { cookieCache?: { enabled?: boolean } };
		};
		return options.session?.cookieCache?.enabled ? undefined : role;
	}

	/** The member row of `userId` in `organizationId` (`organization()` plugin), or `null`. */
	protected async findMember(
		userId: string,
		organizationId: string,
	): Promise<{ role: string } | null> {
		const { ctx, options } = await this.#organization();
		return getOrgAdapter(ctx, options).findMemberByOrgId({
			userId,
			organizationId,
		});
	}

	/**
	 * Whether the user's member role grants `permissions` in the organization.
	 * Merges the roles stored in `organizationRole` when
	 * `dynamicAccessControl` is on.
	 */
	protected async memberHasPermission(
		user: BetterAuthUser,
		organizationId: string,
		permissions: PermissionCheck,
	): Promise<boolean> {
		const member = await this.findMember(user.id, organizationId);
		if (!member) return false;

		const { ctx, options } = await this.#organization();
		// hasPermission only reads `ctx.context` (its adapter and logger).
		return hasPermission(
			{ role: member.role, options, organizationId, permissions },
			{ context: ctx } as Parameters<typeof hasPermission>[1],
		);
	}

	/** Better Auth's context and the `organization()` plugin's options. */
	async #organization() {
		const ctx = await this.betterAuth.instance.$context;
		// biome-ignore lint/suspicious/noExplicitAny: the organization plugin's option types vary by configuration
		const options: any =
			findPlugin(this.betterAuth.instance, "organization")?.options ?? {};
		return { ctx, options };
	}
}
