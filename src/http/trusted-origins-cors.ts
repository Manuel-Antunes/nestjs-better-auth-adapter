import type {
	HttpRequestLike as RequestLike,
	HttpResponseLike as ResponseLike,
	NodeResponseLike,
	TrustedOriginsCorsOptions,
} from "../interfaces/http.interface.ts";
import { getNodeRequest, getNodeResponse } from "./middlewares.ts";

function getHeaderValue(header: string | string[] | undefined) {
	if (Array.isArray(header)) {
		return header.join(", ");
	}

	return header;
}

function appendVaryHeader(res: NodeResponseLike, value: string) {
	const currentHeader = res.getHeader("Vary");
	const currentValue =
		typeof currentHeader === "number"
			? String(currentHeader)
			: Array.isArray(currentHeader)
				? currentHeader.join(", ")
				: currentHeader;

	const varyValues = new Set(
		currentValue
			?.split(",")
			.map((item) => item.trim())
			.filter(Boolean) ?? [],
	);
	varyValues.add(value);

	res.setHeader("Vary", Array.from(varyValues).join(", "));
}

/**
 * CORS for Better Auth's routes, on either adapter: the origins Better Auth
 * trusts, with credentials. Answers preflights itself (`true`); other
 * requests get their headers and go on (`false`). Origins it doesn't trust
 * get no CORS headers, and Better Auth's own origin check still applies.
 */
export function handleTrustedOriginsCors(
	req: RequestLike,
	res: ResponseLike,
	{ isTrustedOrigin }: TrustedOriginsCorsOptions,
) {
	const nodeReq = getNodeRequest(req) as RequestLike;
	const nodeRes = getNodeResponse(res) as NodeResponseLike;
	const origin = getHeaderValue(nodeReq.headers.origin);

	if (!origin || !isTrustedOrigin(origin)) {
		return false;
	}

	nodeRes.setHeader("Access-Control-Allow-Origin", origin);
	nodeRes.setHeader("Access-Control-Allow-Credentials", "true");
	appendVaryHeader(nodeRes, "Origin");

	if (nodeReq.method?.toUpperCase() !== "OPTIONS") {
		return false;
	}

	const requestMethod = getHeaderValue(
		nodeReq.headers["access-control-request-method"],
	);
	const requestHeaders = getHeaderValue(
		nodeReq.headers["access-control-request-headers"],
	);

	nodeRes.setHeader(
		"Access-Control-Allow-Methods",
		requestMethod ?? "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
	);

	if (requestHeaders) {
		nodeRes.setHeader("Access-Control-Allow-Headers", requestHeaders);
		appendVaryHeader(nodeRes, "Access-Control-Request-Headers");
	}

	nodeRes.statusCode = 204;
	nodeRes.setHeader("Content-Length", "0");
	nodeRes.end();

	return true;
}

/**
 * Better Auth's `isTrustedOrigin()`, its own `trustedOrigins` matching
 * (wildcards, IP ranges, `BETTER_AUTH_TRUSTED_ORIGINS`), remembered per
 * origin: a request carries one, and the patterns don't change. Bounded, as
 * origins come from clients.
 */
export function cachedOriginCheck(
	isTrustedOrigin: (origin: string) => boolean,
	limit = 1000,
): (origin: string) => boolean {
	const answers = new Map<string, boolean>();
	return (origin) => {
		let trusted = answers.get(origin);
		if (trusted === undefined) {
			trusted = isTrustedOrigin(origin);
			if (answers.size >= limit) answers.clear();
			answers.set(origin, trusted);
		}
		return trusted;
	};
}
