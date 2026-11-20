import { createHmac, timingSafeEqual } from "node:crypto";
import {
	Body,
	Controller,
	Get,
	Headers,
	HttpCode,
	Post,
	Put,
	Req,
	UnauthorizedException,
} from "@nestjs/common";
import {
	Authenticate,
	AuthenticationContext,
	CurrentUser,
	Public,
} from "@nestjs/authentication";
import { Can } from "@nestjs/authorization";
import { activeOrganization } from "nestjs-better-auth-adapter/authorization";
import type { User } from "../auth/auth.types.ts";
import { InjectEnv } from "../config/config.module.ts";
import type { Env } from "../config/env.ts";
import { BillingPolicy } from "./billing.policy.ts";
import { BillingService } from "./billing.service.ts";
import { BillingWebhookDto, ChangePlanDto } from "./dto/billing.dto.ts";

/** The active organization's subscription. */
@Controller("billing")
export class BillingController {
	constructor(
		private readonly billing: BillingService,
		private readonly auth: AuthenticationContext,
	) {}

	@Get()
	@Can(BillingPolicy, "read", activeOrganization)
	get() {
		return this.billing.get(this.activeOrganizationId());
	}

	/** Costs money: a session that passed a second factor, on top of the role. */
	@Put("plan")
	@Authenticate({ mfa: true })
	@Can(BillingPolicy, "update", activeOrganization)
	changePlan(@Body() body: ChangePlanDto, @CurrentUser() user: User) {
		return this.billing.changePlan(
			this.activeOrganizationId(),
			body.plan,
			user.id,
		);
	}

	/** `@Can()` already checked it is set. */
	private activeOrganizationId(): string {
		return this.auth.session?.activeOrganizationId as string;
	}
}

/**
 * The payment provider's webhook. Public (no user), authenticated by an
 * HMAC of the raw body: `bodyParser.rawBody` keeps `req.rawBody` for it.
 */
@Controller("billing/webhooks")
export class BillingWebhookController {
	constructor(
		private readonly billing: BillingService,
		@InjectEnv() private readonly env: Env,
	) {}

	@Public()
	@Post()
	@HttpCode(204)
	async receive(
		@Req() req: { rawBody?: Buffer },
		@Headers("x-acme-signature") signature: string | undefined,
		@Body() body: BillingWebhookDto,
	) {
		if (!req.rawBody || !this.verify(req.rawBody, signature)) {
			throw new UnauthorizedException("Invalid signature");
		}
		await this.billing.changeStatus(body.organizationId, body.status);
	}

	private verify(rawBody: Buffer, signature: string | undefined) {
		if (!signature) return false;
		const expected = createHmac("sha256", this.env.BILLING_WEBHOOK_SECRET)
			.update(rawBody)
			.digest();
		const given = Buffer.from(signature, "hex");
		return given.length === expected.length && timingSafeEqual(given, expected);
	}
}
