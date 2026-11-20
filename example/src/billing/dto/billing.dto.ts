import { IsIn, IsString } from "class-validator";
import type { BillingStatus, Plan } from "../billing.service.ts";

export class ChangePlanDto {
	@IsIn(["free", "pro", "enterprise"])
	plan!: Plan;
}

export class BillingWebhookDto {
	@IsString()
	organizationId!: string;

	@IsIn(["active", "past_due", "canceled"])
	status!: BillingStatus;
}
