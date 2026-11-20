import { Module } from "@nestjs/common";
import { BetterAuthPermissionPolicy } from "./permission.policy.ts";

/** Provides {@link BetterAuthPermissionPolicy}. */
@Module({
	providers: [BetterAuthPermissionPolicy],
	exports: [BetterAuthPermissionPolicy],
})
export class BetterAuthAuthorizationModule {}
