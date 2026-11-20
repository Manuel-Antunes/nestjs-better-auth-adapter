import type { IncomingMessage, ServerResponse } from "node:http";
import { createRequire } from "node:module";
import type { BetterAuthModuleOptions } from "../interfaces/better-auth-module-options.interface.ts";
import type {
	ResolvedBodyParserOptions,
	SkipBodyParsingMiddlewareOptions,
} from "../interfaces/body-parser-options.interface.ts";
import type {
	ExpressBodyParserModule,
	HttpRequestLike as RequestLike,
	HttpResponseLike as ResponseLike,
	MiddlewareNext,
} from "../interfaces/http.interface.ts";

const require = createRequire(import.meta.url);

/**
 * Raw body parser verify callback.
 * Same implementation as NestJS's rawBodyParser.
 * @see https://github.com/nestjs/nest/blob/master/packages/platform-express/adapters/utils/get-body-parser-options.util.ts
 */
const rawBodyParser = (
	req: IncomingMessage & { rawBody?: Buffer },
	_res: ServerResponse,
	buffer: Buffer,
) => {
	if (Buffer.isBuffer(buffer)) {
		req.rawBody = buffer;
	}
	return true;
};

function getExpressBodyParser(): ExpressBodyParserModule {
	return require("express") as ExpressBodyParserModule;
}

export function resolveBodyParserOptions(
	options: Pick<BetterAuthModuleOptions, "bodyParser"> = {},
): ResolvedBodyParserOptions {
	const jsonOptions = options.bodyParser?.json;
	const urlencodedOptions = options.bodyParser?.urlencoded;
	const rawBody = options.bodyParser?.rawBody ?? false;

	const { enabled: jsonEnabled = true, ...jsonParserOptions } =
		jsonOptions ?? {};
	const {
		enabled: urlencodedEnabled = true,
		extended = true,
		...urlencodedParserOptions
	} = urlencodedOptions ?? {};

	return {
		json: {
			enabled: jsonEnabled,
			rawBody,
			...jsonParserOptions,
		},
		urlencoded: {
			enabled: urlencodedEnabled,
			extended,
			...urlencodedParserOptions,
		},
	};
}

export function getRequestPath(req: RequestLike) {
	return req.originalUrl ?? req.url ?? req.baseUrl ?? req.raw?.url ?? "";
}

export function getNodeRequest(req: RequestLike) {
	return req.raw ?? req;
}

export function getNodeResponse(res: ResponseLike) {
	return res.raw ?? res;
}

export function matchesBasePath(req: RequestLike, basePath: string) {
	const requestPath = getRequestPath(req).split("?", 1)[0] ?? "";

	return requestPath === basePath || requestPath.startsWith(`${basePath}/`);
}

/**
 * Factory that returns a Nest middleware which skips body parsing for the
 * configured basePath.
 */
export function SkipBodyParsingMiddleware(
	options: SkipBodyParsingMiddlewareOptions = {},
) {
	const { basePath = "/api/auth", bodyParser = resolveBodyParserOptions() } =
		options;
	const express = getExpressBodyParser();

	const {
		enabled: jsonEnabled,
		rawBody,
		...jsonParserOptions
	} = bodyParser.json;
	const { enabled: urlencodedEnabled, ...urlencodedParserOptions } =
		bodyParser.urlencoded;

	const expressJsonParserOptions = rawBody
		? { ...jsonParserOptions, verify: rawBodyParser }
		: jsonParserOptions;
	const jsonParser = jsonEnabled
		? express.json(expressJsonParserOptions as never)
		: null;
	const urlencodedParser = urlencodedEnabled
		? express.urlencoded(urlencodedParserOptions as never)
		: null;

	return (req: RequestLike, res: ResponseLike, next: MiddlewareNext): void => {
		if (matchesBasePath(req, basePath)) {
			next();
			return;
		}

		const nodeReq = getNodeRequest(req);
		const nodeRes = getNodeResponse(res);

		const runUrlencodedParser = (err?: unknown) => {
			if (err) {
				next(err);
				return;
			}

			if (!urlencodedParser) {
				next();
				return;
			}

			urlencodedParser(nodeReq, nodeRes, next);
		};

		if (!jsonParser) {
			runUrlencodedParser();
			return;
		}

		jsonParser(nodeReq, nodeRes, runUrlencodedParser);
	};
}
