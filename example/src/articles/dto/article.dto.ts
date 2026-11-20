import { IsOptional, IsString, Length, MaxLength } from "class-validator";

export class CreateArticleDto {
	@IsString()
	@Length(1, 200)
	title!: string;

	@IsString()
	@MaxLength(50_000)
	body!: string;
}

export class UpdateArticleDto {
	@IsOptional()
	@IsString()
	@Length(1, 200)
	title?: string;

	@IsOptional()
	@IsString()
	@MaxLength(50_000)
	body?: string;
}
