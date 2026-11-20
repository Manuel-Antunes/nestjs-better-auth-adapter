import { Injectable } from "@nestjs/common";
import { EventEmitter2 } from "@nestjs/event-emitter";
import { eq } from "drizzle-orm";
import { AppEvent } from "../common/enums/app-event.enum.ts";
import { type BillingChangedEvent } from "../common/events.ts";
import type { Database } from "../database/create-database.ts";
import { InjectDrizzle } from "@nestjs/drizzle";
import {
	type OrganizationBillingRow,
	organizationBilling,
} from "../database/schema/index.ts";

export type Plan = OrganizationBillingRow["plan"];
export type BillingStatus = OrganizationBillingRow["status"];

@Injectable()
export class BillingService {
	constructor(
		@InjectDrizzle() private readonly db: Database,
		private readonly events: EventEmitter2,
	) {}

	/** An organization without a row is on the free plan. */
	async get(organizationId: string) {
		const [row] = await this.db
			.select()
			.from(organizationBilling)
			.where(eq(organizationBilling.organizationId, organizationId));
		return {
			organizationId,
			plan: row?.plan ?? "free",
			status: row?.status ?? "active",
		};
	}

	/** Whether the organization may change anything: not while an invoice is unpaid. */
	async isWritable(organizationId: string) {
		return (await this.get(organizationId)).status !== "past_due";
	}

	changePlan(organizationId: string, plan: Plan, actorId: string) {
		return this.save(organizationId, { plan }, actorId);
	}

	/** Called by the payment provider's webhook. */
	changeStatus(organizationId: string, status: BillingStatus) {
		return this.save(organizationId, { status }, null);
	}

	private async save(
		organizationId: string,
		changes: Partial<Pick<OrganizationBillingRow, "plan" | "status">>,
		actorId: string | null,
	) {
		const [row] = await this.db
			.insert(organizationBilling)
			.values({ organizationId, ...changes })
			.onConflictDoUpdate({
				target: organizationBilling.organizationId,
				set: changes,
			})
			.returning();
		this.events.emit(AppEvent.BillingChanged, {
			organizationId,
			actorId,
			plan: row.plan,
			status: row.status,
		} satisfies BillingChangedEvent);
		return row;
	}
}
