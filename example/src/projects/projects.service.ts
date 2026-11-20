import { Injectable, NotFoundException } from "@nestjs/common";
import { AuthenticationContext } from "@nestjs/authentication";
import { EventEmitter2 } from "@nestjs/event-emitter";
import { and, asc, eq } from "drizzle-orm";
import { AppEvent } from "../common/enums/app-event.enum.ts";
import { type ProjectCreatedEvent } from "../common/events.ts";
import type { Database } from "../database/create-database.ts";
import { InjectDrizzle } from "@nestjs/drizzle";
import { projects } from "../database/schema/index.ts";

export interface ProjectInput {
	name: string;
	description?: string | null;
}

/**
 * Every query is scoped by organization: a project id from another
 * organization is a 404, whatever the caller's role there.
 */
@Injectable()
export class ProjectsService {
	constructor(
		@InjectDrizzle() private readonly db: Database,
		private readonly events: EventEmitter2,
		// The signed-in user and session, without passing the request around.
		private readonly auth: AuthenticationContext,
	) {}

	/** The session's active organization, which `@Can(..., activeOrganization)` already checked. */
	activeOrganizationId(): string {
		const id = this.auth.session?.activeOrganizationId;
		if (!id) throw new NotFoundException("No active organization");
		return id;
	}

	list(organizationId: string) {
		return this.db
			.select()
			.from(projects)
			.where(eq(projects.organizationId, organizationId))
			.orderBy(asc(projects.createdAt));
	}

	async create(organizationId: string, input: ProjectInput) {
		const user = this.auth.requireUser();
		const [project] = await this.db
			.insert(projects)
			.values({ ...input, organizationId, createdBy: user.id })
			.returning();
		this.events.emit(AppEvent.ProjectCreated, {
			organizationId,
			projectId: project.id,
			name: project.name,
			createdBy: user.id,
		} satisfies ProjectCreatedEvent);
		return project;
	}

	async update(
		organizationId: string,
		id: string,
		input: Partial<ProjectInput>,
	) {
		const [project] = await this.db
			.update(projects)
			.set(input)
			.where(
				and(eq(projects.id, id), eq(projects.organizationId, organizationId)),
			)
			.returning();
		if (!project) throw new NotFoundException("Project not found");
		return project;
	}

	async remove(organizationId: string, id: string) {
		const [project] = await this.db
			.delete(projects)
			.where(
				and(eq(projects.id, id), eq(projects.organizationId, organizationId)),
			)
			.returning({ id: projects.id });
		if (!project) throw new NotFoundException("Project not found");
	}
}
