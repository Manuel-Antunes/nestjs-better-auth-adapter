import { randomUUID } from "node:crypto";
import type { IncomingHttpHeaders } from "node:http";
import { ClsMiddleware, type ClsMiddlewareOptions } from "nestjs-cls";
import { RequestMetadata } from "./request-metadata.ts";

/** What the request context needs from Express and Fastify requests alike. */
interface RequestLike {
	headers: IncomingHttpHeaders;
	ip?: string;
	socket?: { remoteAddress?: string };
}

const header = (req: RequestLike, name: string) => {
	const value = req.headers[name];
	return (Array.isArray(value) ? value[0] : value) ?? null;
};

/** One context per request: an id (the caller's `x-request-id`, or a new one) and who is calling. */
export const requestContextOptions: Omit<ClsMiddlewareOptions, "mount"> = {
	generateId: true,
	idGenerator: (req: RequestLike) =>
		header(req, "x-request-id") ?? randomUUID(),
	resolveProxyProviders: false,
	setup: (cls, req: RequestLike) => {
		cls.proxy.set(RequestMetadata, {
			requestId: cls.getId(),
			ipAddress:
				header(req, "x-forwarded-for")?.split(",")[0]?.trim() ??
				req.ip ??
				req.socket?.remoteAddress ??
				null,
			userAgent: header(req, "user-agent"),
		});
	},
};

/**
 * The same context for `BetterAuthModule`'s `middleware` option: Better Auth's
 * routes don't go through Nest's middleware, so they open it themselves.
 */
export const requestContextMiddleware = new ClsMiddleware(requestContextOptions)
	.use;
