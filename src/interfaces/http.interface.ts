import type { IncomingMessage, ServerResponse } from "node:http";
import type { HttpAdapterHost } from "@nestjs/core";

/** A request of either HTTP adapter: Express's, or Fastify's with its Node request in `raw`. */
export type HttpRequestLike = IncomingMessage & {
	raw?: IncomingMessage;
	originalUrl?: string;
	url?: string;
	baseUrl?: string;
};

/** A response of either HTTP adapter: Express's, or Fastify's with its Node response in `raw`. */
export type HttpResponseLike = ServerResponse<IncomingMessage> & {
	raw?: ServerResponse<IncomingMessage>;
};

/** A Node response, with the header methods CORS needs. */
export type NodeResponseLike = ServerResponse<IncomingMessage> & {
	getHeader(name: string): number | string | string[] | undefined;
	setHeader(
		name: string,
		value: number | string | readonly string[],
	): ServerResponse<IncomingMessage>;
	statusCode: number;
};

export type MiddlewareNext = (error?: unknown) => void;

/** One of Express's body parsers. */
export type BodyParserHandler = (
	req: IncomingMessage,
	res: ServerResponse<IncomingMessage>,
	next: MiddlewareNext,
) => void;

/** The body parsers Express ships. */
export type ExpressBodyParserModule = {
	json(options?: unknown): BodyParserHandler;
	urlencoded(options?: unknown): BodyParserHandler;
};

export type FastifyBodyParserDone = (err: Error | null, body?: unknown) => void;

export type FastifyBodyParserHandler = (
	body: Buffer,
	done: FastifyBodyParserDone,
) => void;

/** `FastifyAdapter.useBodyParser()`, typed without importing `@nestjs/platform-fastify`. */
export type FastifyUseBodyParser = (
	type: string | string[] | RegExp,
	rawBody: boolean,
	options?: { bodyLimit?: number },
	parser?: (
		request: unknown,
		body: Buffer,
		done: FastifyBodyParserDone,
	) => void,
) => void;

export type FastifyHttpAdapter = HttpAdapterHost["httpAdapter"] & {
	useBodyParser?: FastifyUseBodyParser;
};

export type QsModule = typeof import("qs");

export interface TrustedOriginsCorsOptions {
	/** Whether Better Auth trusts this origin. */
	isTrustedOrigin(origin: string): boolean;
}
