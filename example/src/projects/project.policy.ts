import { Policy, type PolicyBefore } from "@nestjs/authorization";
import type { BetterAuthUser } from "nestjs-better-auth-adapter";
import { BetterAuthOrganizationACPolicy } from "nestjs-better-auth-adapter/authorization";
import { OrganizationRole } from "../authorization/enums/organization-role.enum.ts";
import { BillingService } from "../billing/billing.service.ts";
import { Project } from "./entities/project.entity.ts";
import { ProjectAction } from "./enums/project-action.enum.ts";

/**
 * Projects belong to organizations: abilities are checked with the
 * organization plugin's access control, for the member's role in the
 * organization each ability receives (`activeOrganization`, a route
 * parameter…). Roles created at runtime with `dynamicAccessControl` count too.
 */
@Policy()
export class ProjectPolicy
	extends BetterAuthOrganizationACPolicy<OrganizationRole, ProjectAction>(
		Project,
		{
			// Required: the generics alone are erased at runtime.
			actions: Object.values(ProjectAction),
			wildcard: ProjectAction.Manage,
			statements: {
				[OrganizationRole.Owner]: [ProjectAction.Manage],
				[OrganizationRole.Admin]: [
					ProjectAction.Create,
					ProjectAction.Read,
					ProjectAction.Update,
					ProjectAction.Delete,
				],
				[OrganizationRole.Member]: [ProjectAction.Create, ProjectAction.Read],
			},
		},
	)
	implements PolicyBefore<BetterAuthUser, ProjectAction>
{
	// A policy is a provider: it injects what it needs, next to the mixin's
	// own BetterAuthService (property-injected, nothing to forward).
	constructor(private readonly billing: BillingService) {
		super();
	}

	/**
	 * Runs before every ability: an organization with an unpaid invoice can
	 * still read its projects, not change them. `undefined` falls through to
	 * the role check.
	 */
	async before(
		_user: BetterAuthUser | null,
		ability: ProjectAction,
		organizationId?: string | null,
	) {
		if (ability === ProjectAction.Read || !organizationId) return undefined;
		if (!(await this.billing.isWritable(organizationId))) return false;
		return undefined;
	}
}
