import { Injectable } from "@nestjs/common";
import { EventEmitter2 } from "@nestjs/event-emitter";
import {
	AfterCreate,
	BeforeCreate,
	BetterAuthService,
	DatabaseHook,
} from "nestjs-better-auth-adapter";
import { AppEvent } from "../../common/enums/app-event.enum.ts";
import {
	type AccountLinkedEvent,
	type SessionCreatedEvent,
} from "../../common/events.ts";
import type { Auth } from "../create-auth.ts";
import type { AccountRow } from "../interfaces/account-row.interface.ts";
import type { SessionRow } from "../interfaces/session-row.interface.ts";

/** Better Auth database hooks for sessions and accounts. */
@DatabaseHook()
@Injectable()
export class SessionDatabaseHooks {
	constructor(
		private readonly betterAuth: BetterAuthService<Auth>,
		private readonly events: EventEmitter2,
	) {}

	/**
	 * New sessions start in the user's first organization, so `@Can(...,
	 * activeOrganization)` routes work right after sign-in.
	 */
	@BeforeCreate("session")
	async startInFirstOrganization(session: SessionRow) {
		if (session.activeOrganizationId) return;
		const ctx = await this.betterAuth.instance.$context;
		const membership = await ctx.adapter.findOne<{ organizationId: string }>({
			model: "member",
			where: [{ field: "userId", value: session.userId }],
		});
		if (!membership) return;
		return { data: { activeOrganizationId: membership.organizationId } };
	}

	@AfterCreate("session")
	announceSession(session: SessionRow) {
		this.events.emit(AppEvent.SessionCreated, {
			userId: session.userId,
			sessionId: session.id,
			ipAddress: session.ipAddress ?? null,
			userAgent: session.userAgent ?? null,
		} satisfies SessionCreatedEvent);
	}

	@AfterCreate("account")
	announceLinkedAccount(account: AccountRow) {
		if (account.providerId === "credential") return;
		this.events.emit(AppEvent.AccountLinked, {
			userId: account.userId,
			providerId: account.providerId,
		} satisfies AccountLinkedEvent);
	}
}
