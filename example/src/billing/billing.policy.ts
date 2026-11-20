import { Policy } from "@nestjs/authorization";
import { BetterAuthOrganizationACPolicy } from "nestjs-better-auth-adapter/authorization";
import { OrganizationRole } from "../authorization/enums/organization-role.enum.ts";

/**
 * An organization's subscription. The resource is a plain string, and the
 * roles and actions are inferred from the config: abilities `read`, `update`.
 * The custom `billing` role exists only through this policy:
 * `BetterAuthAccessControl.organization()` adds it to the organization
 * plugin's roles, next to Better Auth's owner/admin/member.
 */
@Policy()
export class BillingPolicy extends BetterAuthOrganizationACPolicy("billing", {
	statements: {
		[OrganizationRole.Owner]: ["read", "update"],
		[OrganizationRole.Billing]: ["read", "update"],
		[OrganizationRole.Admin]: ["read"],
	},
}) {}
