import type { IncomingHttpHeaders } from "node:http";

/**
 * The request behind a call, as far as authentication reads it: its
 * headers, and its method and URL where the transport has them (a
 * WebSocket handshake has no method, so it never counts as a safe request).
 */
export interface BetterAuthRequest {
	headers: IncomingHttpHeaders;
	method?: string;
	url?: string;
}

/** @internal The transports a request is read from, as `@nestjs/authentication` reads them. */
export type ContextType = "graphql" | "ws" | "http" | "rpc" | "mcp" | "ai";
