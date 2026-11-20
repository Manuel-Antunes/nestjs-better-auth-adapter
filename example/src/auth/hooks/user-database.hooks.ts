import { Injectable } from "@nestjs/common";
import { EventEmitter2 } from "@nestjs/event-emitter";
import { and, eq } from "drizzle-orm";
import {
	AfterCreate,
	AfterDelete,
	AfterUpdate,
	BeforeCreate,
	BeforeDelete,
	BeforeUpdate,
	DatabaseHook,
} from "nestjs-better-auth-adapter";
import { AppEvent } from "../../common/enums/app-event.enum.ts";
import { type UserEvent, type UserUpdatedEvent } from "../../common/events.ts";
import type { Database } from "../../database/create-database.ts";
import { InjectDrizzle } from "@nestjs/drizzle";
import { articles } from "../../database/schema/index.ts";
import type { UserRow } from "../interfaces/user-row.interface.ts";

/**
 * Better Auth database hooks for users, as a Nest provider. `before` hooks
 * may return `{ data }` to change the write, `false` to cancel it, or throw
 * an `APIError` to refuse the request; `after` hooks see the stored row.
 */
@DatabaseHook()
@Injectable()
export class UserDatabaseHooks {
	constructor(
		@InjectDrizzle() private readonly db: Database,
		private readonly events: EventEmitter2,
	) {}

	@BeforeCreate("user")
	normalizeNewUser(user: UserRow) {
		return {
			data: { email: user.email.trim().toLowerCase(), name: user.name.trim() },
		};
	}

	@BeforeUpdate("user")
	normalizeUserUpdate(changes: Partial<UserRow>) {
		if (typeof changes.name !== "string") return;
		return { data: { name: changes.name.trim() } };
	}

	@AfterCreate("user")
	announceNewUser(user: UserRow) {
		this.events.emit(AppEvent.UserRegistered, {
			userId: user.id,
			email: user.email,
			name: user.name,
		} satisfies UserEvent);
	}

	@AfterUpdate("user")
	announceUserUpdate(user: UserRow) {
		this.events.emit(AppEvent.UserUpdated, {
			userId: user.id,
			role: user.role ?? null,
			banned: !!user.banned,
			emailVerified: !!user.emailVerified,
		} satisfies UserUpdatedEvent);
	}

	/**
	 * Drafts go with their author; published articles stay, anonymized by the
	 * foreign key (`on delete set null`).
	 *
	 * Don't refuse the deletion here (`false` or a throw): Better Auth deletes
	 * the user's sessions and accounts, password included, before this hook
	 * runs. Refusals belong in a request hook: see `AuthRequestHooks`.
	 */
	@BeforeDelete("user")
	async deleteDrafts(user: UserRow) {
		await this.db
			.delete(articles)
			.where(and(eq(articles.authorId, user.id), eq(articles.status, "draft")));
	}

	@AfterDelete("user")
	announceDeletedUser(user: UserRow) {
		this.events.emit(AppEvent.UserDeleted, {
			userId: user.id,
			email: user.email,
			name: user.name,
		} satisfies UserEvent);
	}
}
