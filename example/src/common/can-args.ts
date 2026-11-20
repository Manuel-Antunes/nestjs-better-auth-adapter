import type { ExecutionContext } from "@nestjs/common";
import { GqlExecutionContext } from "@nestjs/graphql";

/*
 * `@Can()` argument resolvers: they run in the guard, before pipes, and pass
 * identifiers (never records) to the policy ability. For the session's active
 * organization, use `activeOrganization` from
 * `nestjs-better-auth-adapter/authorization`.
 */

/** A route parameter: `@Can(ProjectPolicy, 'read', routeParam('organizationId'))`. */
export const routeParam = (name: string) => (context: ExecutionContext) =>
	[
		context.switchToHttp().getRequest<{ params: Record<string, string> }>()
			.params[name] ?? null,
	] as const;

/** A query string parameter. */
export const queryParam = (name: string) => (context: ExecutionContext) => {
	const value = context
		.switchToHttp()
		.getRequest<{ query: Record<string, unknown> }>().query[name];
	return [typeof value === "string" ? value : null] as const;
};

/** A GraphQL argument. */
export const graphqlArg = (name: string) => (context: ExecutionContext) => {
	const value = GqlExecutionContext.create(context).getArgs()[name];
	return [typeof value === "string" ? value : null] as const;
};

/** A field of a WebSocket message's payload. */
export const messageField = (name: string) => (context: ExecutionContext) => {
	const data = context.switchToWs().getData<Record<string, unknown>>();
	const value = data?.[name];
	return [typeof value === "string" ? value : null] as const;
};
