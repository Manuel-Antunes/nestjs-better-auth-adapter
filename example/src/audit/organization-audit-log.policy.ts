import { Policy } from "@nestjs/authorization";
import { BetterAuthOrganizationACPolicy } from "nestjs-better-auth-adapter/authorization";
import { OrganizationRole } from "../authorization/enums/organization-role.enum.ts";
import { AuditLog } from "./entities/audit-log.entity.ts";

/**
 * An organization's own audit trail (its projects, its billing), checked
 * with the organization plugin's access control for the member's role in
 * that organization. Owners and admins read it. Its `audit-log` statements
 * live in the organization plugin's `ac`, apart from the platform's
 * {@link AuditLogPolicy}, in the admin plugin's.
 */
@Policy()
export class OrganizationAuditLogPolicy extends BetterAuthOrganizationACPolicy(
	AuditLog,
	{
		statements: {
			[OrganizationRole.Owner]: ["read"],
			[OrganizationRole.Admin]: ["read"],
		},
	},
) {}
