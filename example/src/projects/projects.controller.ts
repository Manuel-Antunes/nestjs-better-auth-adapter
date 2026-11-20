import {
	Body,
	Controller,
	Delete,
	Get,
	HttpCode,
	Param,
	ParseUUIDPipe,
	Patch,
	Post,
} from "@nestjs/common";
import { Authenticate } from "@nestjs/authentication";
import { Can } from "@nestjs/authorization";
import { activeOrganization } from "nestjs-better-auth-adapter/authorization";
import { routeParam } from "../common/can-args.ts";
import { CreateProjectDto, UpdateProjectDto } from "./dto/project.dto.ts";
import { ProjectPolicy } from "./project.policy.ts";
import { ProjectsService } from "./projects.service.ts";

/** Projects of the session's active organization (`activeOrganizationId`). */
@Controller("projects")
export class ProjectsController {
	constructor(private readonly projects: ProjectsService) {}

	@Get()
	@Can(ProjectPolicy, "read", activeOrganization)
	list() {
		return this.projects.list(this.projects.activeOrganizationId());
	}

	@Post()
	@Can(ProjectPolicy, "create", activeOrganization)
	create(@Body() body: CreateProjectDto) {
		return this.projects.create(this.projects.activeOrganizationId(), body);
	}

	@Patch(":id")
	@Can(ProjectPolicy, "update", activeOrganization)
	update(
		@Param("id", ParseUUIDPipe) id: string,
		@Body() body: UpdateProjectDto,
	) {
		return this.projects.update(this.projects.activeOrganizationId(), id, body);
	}

	/** Destructive: the role allows it, and the session passed a second factor. */
	@Delete(":id")
	@HttpCode(204)
	@Authenticate({ mfa: true })
	@Can(ProjectPolicy, "delete", activeOrganization)
	remove(@Param("id", ParseUUIDPipe) id: string) {
		return this.projects.remove(this.projects.activeOrganizationId(), id);
	}
}

/** The same projects, for any organization named in the URL: the caller's role there decides. */
@Controller("organizations/:organizationId/projects")
export class OrganizationProjectsController {
	constructor(private readonly projects: ProjectsService) {}

	@Get()
	@Can(ProjectPolicy, "read", routeParam("organizationId"))
	list(@Param("organizationId") organizationId: string) {
		return this.projects.list(organizationId);
	}
}
