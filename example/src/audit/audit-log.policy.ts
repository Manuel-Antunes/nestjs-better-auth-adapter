import { Policy } from "@nestjs/authorization";
import { PlatformPolicy } from "../authorization/platform-policy.ts";
import { PlatformRole } from "../authorization/enums/platform-role.enum.ts";
import { AuditLog } from "./entities/audit-log.entity.ts";

/**
 * Who reads the audit trail: support reads it, admins also export it
 * (`manage`, granted by the mixin). Abilities: `read`, `export`, `manage`.
 */
@Policy()
export class AuditLogPolicy extends PlatformPolicy(AuditLog, {
	actions: ["read", "export"],
	statements: { [PlatformRole.Support]: ["read"] },
}) {}
