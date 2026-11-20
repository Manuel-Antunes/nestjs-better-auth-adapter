import type { HttpResponseLike } from "../interfaces/http.interface.ts";

/**
 * Adds `Set-Cookie` headers to a response of either adapter, after those
 * already set. Nothing once the headers are sent (a stream), or without a
 * response (WebSockets, RPC).
 */
export function appendSetCookies(
	response:
		| (HttpResponseLike & { header?: (name: string, value: string) => unknown })
		| undefined,
	cookies: readonly string[],
): void {
	if (!response || cookies.length === 0) return;
	const node = response.raw ?? response;
	if (node.headersSent || typeof node.setHeader !== "function") return;

	// Fastify's reply: header('set-cookie') adds a cookie rather than
	// replacing them, and reply.send() writes its own headers over the raw
	// response's.
	if (response.raw && typeof response.header === "function") {
		for (const cookie of cookies) response.header("set-cookie", cookie);
		return;
	}
	const existing = node.getHeader("set-cookie");
	node.setHeader("set-cookie", [
		...(existing === undefined
			? []
			: Array.isArray(existing)
				? existing
				: [String(existing)]),
		...cookies,
	]);
}
