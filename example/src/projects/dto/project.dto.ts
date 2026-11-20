import { Field, InputType } from "@nestjs/graphql";
import { IsOptional, IsString, Length, MaxLength } from "class-validator";

/** The body of `POST /projects`, and the `createProject` mutation's input. */
@InputType()
export class CreateProjectDto {
	@Field(() => String)
	@IsString()
	@Length(1, 120)
	name!: string;

	@Field(() => String, { nullable: true })
	@IsOptional()
	@IsString()
	@MaxLength(2000)
	description?: string;
}

export class UpdateProjectDto {
	@IsOptional()
	@IsString()
	@Length(1, 120)
	name?: string;

	@IsOptional()
	@IsString()
	@MaxLength(2000)
	description?: string;
}
