import { Type } from "class-transformer";
import { IsInt, IsOptional, IsString, Max, Min } from "class-validator";

export class ListAuditEventsQuery {
	@IsOptional()
	@IsString()
	action?: string;

	@IsOptional()
	@IsString()
	actorId?: string;

	@IsOptional()
	@Type(() => Number)
	@IsInt()
	@Min(1)
	@Max(500)
	limit?: number;
}
