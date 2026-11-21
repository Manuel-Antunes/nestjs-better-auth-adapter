import type { ExecutionContext } from "@nestjs/common";
import type { GqlExecutionContext as GqlExecutionContextType } from "@nestjs/graphql";
import type {
	BetterAuthRequest,
	ContextType,
} from "./interfaces/better-auth-request.interface.ts";

let GqlExecutionContext: typeof GqlExecutionContextType | undefined;

async function getGqlExecutionContext(): Promise<
	typeof GqlExecutionContextType
> {
	if (!GqlExecutionContext) {
		GqlExecutionContext = (await import("@nestjs/graphql")).GqlExecutionContext;
	}
	return GqlExecutionContext as typeof GqlExecutionContextType;
}

/**
 * The HTTP request an `@nestjs/mcp` call (a tool, resource or prompt) or an
 * `@nestjs/ai` agent function call arrived in, read from its arguments,
 * `[input, context]`, as `@nestjs/authentication` reads it: neither package
 * is a dependency. `undefined` over stdio, and in a job.
 */
// biome-ignore lint/suspicious/noExplicitAny: the request type depends on the transport
function callRequestOf(context: ExecutionContext): any {
	const call = context.getArgByIndex(1);
	return typeof call === "object" && call !== null ? call.request : undefined;
}

/**
 * Extracts the request object from an HTTP, GraphQL, WebSocket, MCP or agent
 * function execution context.
 * @param context - The execution context
 * @returns The request object
 */
export async function getRequestFromContext(context: ExecutionContext) {
	const contextType = context.getType<ContextType>();
	if (contextType === "mcp" || contextType === "ai") {
		return callRequestOf(context);
	}

	if (contextType === "graphql") {
		return (await getGqlExecutionContext()).create(context).getContext().req;
	}

	if (contextType === "ws") {
		return context.switchToWs().getClient();
	}

	return context.switchToHttp().getRequest();
}

/**
 * The path of the request behind a call, without its query, read
 * synchronously: the HTTP request's (GraphQL's `context.req`, and the one an
 * MCP or agent function call arrived in, included) or a WebSocket's
 * handshake. `undefined` when there is none (RPC).
 */
export function getRequestPathSync(
	context: ExecutionContext,
): string | undefined {
	const contextType = context.getType<ContextType>();
	// biome-ignore lint/suspicious/noExplicitAny: the request type depends on the transport
	let request: any;
	if (contextType === "ws") {
		const client = context.switchToWs().getClient();
		request = client?.handshake ?? client?.request;
	} else if (contextType === "graphql") {
		// A resolver's arguments are (root, args, context, info); a federation
		// reference resolver's, (reference, context, info).
		const args = context.getArgs();
		request = (args.length === 3 ? args[1] : args[2])?.req;
	} else if (contextType === "http") {
		request = context.switchToHttp().getRequest();
	} else if (contextType === "mcp" || contextType === "ai") {
		request = callRequestOf(context);
	}
	const url = request?.originalUrl ?? request?.url ?? request?.raw?.url;
	return typeof url === "string" ? url.split("?", 1)[0] : undefined;
}

/**
 * The request behind a call, as far as authentication needs it, as
 * `@nestjs/authentication` reads it: the HTTP request, GraphQL's
 * `context.req`, a WebSocket's handshake (socket.io's `handshake`, or
 * the upgrade request `WsAuthenticator` keeps on a `ws` client as
 * `client.request`), or the HTTP request an MCP or agent function call
 * arrived in. `undefined` over RPC, and MCP over stdio.
 */
export async function getAuthRequest(
	context: ExecutionContext,
): Promise<BetterAuthRequest | undefined> {
	const contextType = context.getType<ContextType>();
	if (contextType === "ws") {
		const client = context.switchToWs().getClient();
		if (client?.handshake?.headers)
			return { headers: client.handshake.headers, url: client.handshake.url };
		const upgrade = client?.request;
		return upgrade?.headers
			? { headers: upgrade.headers, method: upgrade.method, url: upgrade.url }
			: undefined;
	}
	if (
		contextType !== "http" &&
		contextType !== "graphql" &&
		contextType !== "mcp" &&
		contextType !== "ai"
	)
		return undefined;
	const request = await getRequestFromContext(context);
	return request?.headers ? request : undefined;
}

/**
 * The HTTP response of an HTTP or GraphQL execution context (GraphQL's
 * `context.res`, `context.reply`, or Express's `req.res`), else `undefined`:
 * WebSockets and RPC have none. Wrapped, since Fastify's reply is a
 * thenable: a promise of it would wait for the response to be sent.
 */
export async function getResponseFromContext(
	context: ExecutionContext,
	// biome-ignore lint/suspicious/noExplicitAny: the response type depends on the HTTP adapter
): Promise<{ response: any }> {
	const contextType = context.getType<ContextType>();
	if (contextType === "http")
		return { response: context.switchToHttp().getResponse() };
	if (contextType === "graphql") {
		const gqlContext = (await getGqlExecutionContext())
			.create(context)
			.getContext();
		return {
			response: gqlContext.res ?? gqlContext.reply ?? gqlContext.req?.res,
		};
	}
	return { response: undefined };
}
