import { Controller, Get, Query } from "@nestjs/common";
import { CurrentSession } from "@nestjs/authentication";
import { Can } from "@nestjs/authorization";
import { activeOrganization } from "nestjs-better-auth-adapter/authorization";
import type { Session } from "../auth/auth.types.ts";
import { AuditService } from "./audit.service.ts";
import { ListAuditEventsQuery } from "./list-audit-events.query.ts";
import { OrganizationAuditLogPolicy } from "./organization-audit-log.policy.ts";

/** The active organization's audit trail, for the roles {@link OrganizationAuditLogPolicy} lets read it. */
@Controller("organizations/current/audit-events")
export class OrganizationAuditController {
	constructor(private readonly audit: AuditService) {}

	@Get()
	@Can(OrganizationAuditLogPolicy, "read", activeOrganization)
	list(
		@CurrentSession() session: Session,
		@Query() query: ListAuditEventsQuery,
	) {
		return this.audit.list({
			...query,
			// `@Can()` checked the membership, so it is set.
			organizationId: session.activeOrganizationId as string,
		});
	}
}
