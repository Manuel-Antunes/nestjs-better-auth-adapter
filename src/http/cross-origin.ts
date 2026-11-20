import type { IncomingHttpHeaders } from "node:http";

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const DEFAULT_PORTS: Record<string, string> = {
	"http:": "80",
	"https:": "443",
};

/** Repeated headers are joined, so conflicting values never equal `same-origin` or a trusted origin. */
function header(headers: IncomingHttpHeaders, name: string) {
	const value = headers[name];
	return Array.isArray(value) ? value.join(", ") : value;
}

function originMatchesHost(origin: string, host: string) {
	let url: URL;
	try {
		url = new URL(origin); // `null` (sandboxed frames) and non-URLs never match
	} catch {
		return false;
	}
	if (!url.host) return false;
	const authority = host.toLowerCase();
	if (url.host === authority) return true;
	const port = DEFAULT_PORTS[url.protocol];
	return (
		!url.port && port !== undefined && `${url.hostname}:${port}` === authority
	);
}

/**
 * Whether a request would change state from another origin: the decision
 * `@nestjs/authentication`'s `SessionCookieProvider` makes before reading
 * the session cookie (after Go's `net/http.CrossOriginProtection`), with
 * Better Auth's trusted origins as the exceptions.
 *
 * 1. `GET`, `HEAD` and `OPTIONS` never are.
 * 2. With `Sec-Fetch-Site`, anything but `same-origin` and `none` is.
 * 3. Without it, a request with no `Origin` is not: a non-browser client.
 * 4. Otherwise `Origin` must name the request's host (`:authority` on
 *    HTTP/2, else `Host`), ignoring the scheme's default port.
 *
 * A WebSocket handshake (no method, or a GET with `Upgrade: websocket`)
 * opens a channel that carries writes, so steps 2 to 4 apply to it
 * (cross-site WebSocket hijacking): browsers send cookies on cross-site
 * upgrades.
 */
export function isCrossOriginWrite(
	request: { headers: IncomingHttpHeaders; method?: string },
	isTrustedOrigin: (origin: string) => boolean,
): boolean {
	const upgrade =
		header(request.headers, "upgrade")?.toLowerCase() === "websocket";
	if (
		request.method !== undefined &&
		SAFE_METHODS.has(request.method.toUpperCase()) &&
		!upgrade
	)
		return false;

	const origin = header(request.headers, "origin");
	const site = header(request.headers, "sec-fetch-site");
	if (site !== undefined) {
		if (site === "same-origin" || site === "none") return false;
		return !(origin !== undefined && isTrustedOrigin(origin));
	}
	if (origin === undefined) return false;
	const host =
		header(request.headers, ":authority") ?? header(request.headers, "host");
	if (host !== undefined && originMatchesHost(origin, host)) return false;
	return !isTrustedOrigin(origin);
}
