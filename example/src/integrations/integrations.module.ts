import { Module } from "@nestjs/common";
import { ProjectsModule } from "../projects/projects.module.ts";
import {
	IntegrationsController,
	InternalController,
} from "./integrations.controller.ts";

@Module({
	imports: [ProjectsModule],
	controllers: [IntegrationsController, InternalController],
})
export class IntegrationsModule {}
