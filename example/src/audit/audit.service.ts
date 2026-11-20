import { Injectable, Logger } from "@nestjs/common";
import { OnEvent } from "@nestjs/event-emitter";
import { and, desc, eq, type SQL } from "drizzle-orm";
import { AppEvent } from "../common/enums/app-event.enum.ts";
import {
	type AccountLinkedEvent,
	type BillingChangedEvent,
	type ProjectCreatedEvent,
	type SessionCreatedEvent,
	type SignInFailedEvent,
	type UserEvent,
	type UserUpdatedEvent,
} from "../common/events.ts";
import { RequestMetadata } from "../common/request-metadata.ts";
import type { Database } from "../database/create-database.ts";
import { InjectDrizzle } from "@nestjs/drizzle";
import { auditEvents } from "../database/schema/index.ts";

export interface AuditEntry {
	action: string;
	actorId?: string | null;
	organizationId?: string | null;
	metadata?: Record<string, unknown>;
}

/**
 * The audit trail. Entries carry the request id and IP of the request that
 * caused them, read from {@link RequestMetadata}: that works inside Better
 * Auth's hooks too, since `BetterAuthModule`'s `middleware` opens the
 * context for its routes.
 */
@Injectable()
export class AuditService {
	private readonly logger = new Logger(AuditService.name);

	constructor(
		@InjectDrizzle() private readonly db: Database,
		private readonly request: RequestMetadata,
	) {}

	async record(entry: AuditEntry) {
		await this.db.insert(auditEvents).values({
			action: entry.action,
			actorId: entry.actorId ?? null,
			organizationId: entry.organizationId ?? null,
			metadata: entry.metadata ?? {},
			ipAddress: this.request.ipAddress ?? null,
			requestId: this.request.requestId ?? null,
		});
	}

	list(
		filter: {
			action?: string;
			actorId?: string;
			organizationId?: string;
			limit?: number;
		} = {},
	) {
		const conditions: SQL[] = [];
		if (filter.action) conditions.push(eq(auditEvents.action, filter.action));
		if (filter.actorId)
			conditions.push(eq(auditEvents.actorId, filter.actorId));
		if (filter.organizationId)
			conditions.push(eq(auditEvents.organizationId, filter.organizationId));
		return this.db
			.select()
			.from(auditEvents)
			.where(and(...conditions))
			.orderBy(desc(auditEvents.createdAt))
			.limit(filter.limit ?? 100);
	}

	// What Better Auth's hooks and the app report, recorded without slowing them down.

	@OnEvent(AppEvent.UserRegistered, { async: true })
	onUserRegistered(event: UserEvent) {
		return this.safely({ action: "user.registered", actorId: event.userId });
	}

	@OnEvent(AppEvent.UserUpdated, { async: true })
	onUserUpdated(event: UserUpdatedEvent) {
		return this.safely({
			action: "user.updated",
			actorId: event.userId,
			metadata: {
				role: event.role,
				banned: event.banned,
				emailVerified: event.emailVerified,
			},
		});
	}

	@OnEvent(AppEvent.UserDeleted, { async: true })
	onUserDeleted(event: UserEvent) {
		return this.safely({ action: "user.deleted", actorId: event.userId });
	}

	@OnEvent(AppEvent.SessionCreated, { async: true })
	onSessionCreated(event: SessionCreatedEvent) {
		return this.safely({
			action: "session.created",
			actorId: event.userId,
			metadata: { sessionId: event.sessionId, userAgent: event.userAgent },
		});
	}

	@OnEvent(AppEvent.AccountLinked, { async: true })
	onAccountLinked(event: AccountLinkedEvent) {
		return this.safely({
			action: "account.linked",
			actorId: event.userId,
			metadata: { providerId: event.providerId },
		});
	}

	@OnEvent(AppEvent.SignInFailed, { async: true })
	onSignInFailed(event: SignInFailedEvent) {
		return this.safely({
			action: "auth.sign-in.failed",
			metadata: { ...event },
		});
	}

	@OnEvent(AppEvent.ProjectCreated, { async: true })
	onProjectCreated(event: ProjectCreatedEvent) {
		return this.safely({
			action: "project.created",
			actorId: event.createdBy,
			organizationId: event.organizationId,
			metadata: { projectId: event.projectId, name: event.name },
		});
	}

	@OnEvent(AppEvent.BillingChanged, { async: true })
	onBillingChanged(event: BillingChangedEvent) {
		return this.safely({
			action: "billing.changed",
			actorId: event.actorId,
			organizationId: event.organizationId,
			metadata: { plan: event.plan, status: event.status },
		});
	}

	/** An audit write that fails is logged; it never fails what it records. */
	private async safely(entry: AuditEntry) {
		try {
			await this.record(entry);
		} catch (error) {
			this.logger.error(`Could not record ${entry.action}`, error);
		}
	}
}
