import { Global, Module } from "@nestjs/common";
import { ClsModule } from "nestjs-cls";
import { RequestMetadata } from "../common/request-metadata.ts";
import { AuditController } from "./audit.controller.ts";
import { AuditLogPolicy } from "./audit-log.policy.ts";
import { OrganizationAuditController } from "./organization-audit.controller.ts";
import { OrganizationAuditLogPolicy } from "./organization-audit-log.policy.ts";
import { AuditService } from "./audit.service.ts";

@Global()
@Module({
	// The request's id, IP and user agent, as an injectable.
	imports: [ClsModule.forFeature(RequestMetadata)],
	controllers: [AuditController, OrganizationAuditController],
	// Policies are providers: BetterAuthAccessControl finds them here at startup.
	providers: [AuditService, AuditLogPolicy, OrganizationAuditLogPolicy],
	exports: [AuditService],
})
export class AuditModule {}
