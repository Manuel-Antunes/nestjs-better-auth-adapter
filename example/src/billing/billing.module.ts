import { Module } from "@nestjs/common";
import {
	BillingController,
	BillingWebhookController,
} from "./billing.controller.ts";
import { BillingPolicy } from "./billing.policy.ts";
import { BillingService } from "./billing.service.ts";

@Module({
	controllers: [BillingController, BillingWebhookController],
	providers: [BillingService, BillingPolicy],
	exports: [BillingService],
})
export class BillingModule {}
