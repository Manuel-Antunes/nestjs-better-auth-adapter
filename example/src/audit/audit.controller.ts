import { Controller, Get, Header, Query } from "@nestjs/common";
import { Can } from "@nestjs/authorization";
import { AuditLogPolicy } from "./audit-log.policy.ts";
import { AuditService } from "./audit.service.ts";
import { ListAuditEventsQuery } from "./list-audit-events.query.ts";

@Controller("admin/audit-events")
export class AuditController {
	constructor(private readonly audit: AuditService) {}

	/** Support and admins (`read`, through the admin() plugin's access control). */
	@Get()
	@Can(AuditLogPolicy, "read")
	list(@Query() query: ListAuditEventsQuery) {
		return this.audit.list(query);
	}

	/** Admins only: `export` is granted to admins by the `manage` wildcard. */
	@Get("export")
	@Can(AuditLogPolicy, "export")
	@Header("content-type", "text/csv")
	@Header("content-disposition", 'attachment; filename="audit-events.csv"')
	async export(@Query() query: ListAuditEventsQuery) {
		const rows = await this.audit.list({ ...query, limit: 10_000 });
		const lines = rows.map((row) =>
			[
				row.createdAt.toISOString(),
				row.action,
				row.actorId ?? "",
				row.ipAddress ?? "",
			]
				.map((value) => JSON.stringify(value))
				.join(","),
		);
		return ["created_at,action,actor_id,ip_address", ...lines].join("\n");
	}
}
