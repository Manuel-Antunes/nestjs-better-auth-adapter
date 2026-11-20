import {
	Args,
	Field,
	ID,
	Mutation,
	ObjectType,
	Query,
	Resolver,
} from "@nestjs/graphql";
import { Authenticate, CurrentUser } from "@nestjs/authentication";
import { Can } from "@nestjs/authorization";
import { activeOrganization } from "nestjs-better-auth-adapter/authorization";
import type { User } from "../auth/auth.types.ts";
import { graphqlArg } from "../common/can-args.ts";
import { CreateProjectDto } from "./dto/project.dto.ts";
import { ProjectPolicy } from "./project.policy.ts";
import { ProjectsService } from "./projects.service.ts";

@ObjectType("Project")
class ProjectModel {
	@Field(() => ID)
	id!: string;

	@Field(() => String)
	organizationId!: string;

	@Field(() => String)
	name!: string;

	@Field(() => String, { nullable: true })
	description!: string | null;

	@Field(() => Date)
	createdAt!: Date;
}

@ObjectType("Viewer")
class ViewerModel {
	@Field(() => ID)
	id!: string;

	@Field(() => String)
	name!: string;

	@Field(() => String)
	email!: string;

	@Field(() => Boolean)
	emailVerified!: boolean;
}

/**
 * The same guards as REST: `AuthenticationModule`'s reads the session from
 * the GraphQL request (`context: ({ req, res }) => ({ req, res })`), and
 * `@Can()` resolvers read GraphQL arguments.
 */
@Resolver()
export class ProjectsResolver {
	constructor(private readonly service: ProjectsService) {}

	/** Anonymous callers get `null` rather than an error. */
	@Query(() => ViewerModel, { nullable: true })
	@Authenticate({ optional: true })
	@Can.Anyone()
	viewer(@CurrentUser() user: User | null) {
		return user;
	}

	@Query(() => [ProjectModel])
	@Can(ProjectPolicy, "read", graphqlArg("organizationId"))
	projects(@Args("organizationId", { type: () => ID }) organizationId: string) {
		return this.service.list(organizationId);
	}

	@Mutation(() => ProjectModel)
	@Can(ProjectPolicy, "create", activeOrganization)
	createProject(@Args("input") input: CreateProjectDto) {
		return this.service.create(this.service.activeOrganizationId(), input);
	}
}
