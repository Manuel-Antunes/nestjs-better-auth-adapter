import { Module } from "@nestjs/common";
import { BillingModule } from "../billing/billing.module.ts";
import { ProjectPolicy } from "./project.policy.ts";
import {
	OrganizationProjectsController,
	ProjectsController,
} from "./projects.controller.ts";
import { ProjectsGateway } from "./projects.gateway.ts";
import { ProjectsResolver } from "./projects.resolver.ts";
import { ProjectsService } from "./projects.service.ts";

@Module({
	imports: [BillingModule],
	controllers: [ProjectsController, OrganizationProjectsController],
	providers: [
		ProjectsService,
		ProjectPolicy,
		ProjectsResolver,
		ProjectsGateway,
	],
	exports: [ProjectsService],
})
export class ProjectsModule {}
