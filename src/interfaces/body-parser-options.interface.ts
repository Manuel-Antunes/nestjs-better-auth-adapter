import type { IncomingMessage } from "node:http";
import type { BYTE_UNITS } from "../http/byte-units.ts";

export type BodyParserTypeMatcher =
	| string
	| string[]
	| ((req: IncomingMessage) => unknown);

export type BodyParserByteUnit = keyof typeof BYTE_UNITS;

/**
 * Known body size limit strings: values such as `"300kb"`, `"2mb"`, `"0.5gb"`, or plain digits for bytes (e.g. `"1048576"`).
 */
export type KnownBodyParserLimit =
	| `${number}`
	| `${number}${BodyParserByteUnit}`;

/**
 * Body size limit: a byte count (`number`) or a string limit.
 *
 * String remains accepted for compatibility with Express/body-parser and
 * environment-driven configuration, while known literal forms still show up as
 * TypeScript guidance.
 */
export type BodyParserLimit = number | KnownBodyParserLimit | (string & {});

export interface CommonBodyParserOptions {
	inflate?: boolean;
	limit?: BodyParserLimit;
	type?: BodyParserTypeMatcher;
}

export interface JsonBodyParserOptions extends CommonBodyParserOptions {
	reviver?: (key: string, value: unknown) => unknown;
	strict?: boolean;
}

export interface UrlencodedBodyParserOptions extends CommonBodyParserOptions {
	extended?: boolean;
	parameterLimit?: number;
	charsetSentinel?: boolean;
	defaultCharset?: string;
	interpretNumericEntities?: boolean;
	depth?: number;
}

export type BetterAuthJsonBodyParserOptions = JsonBodyParserOptions & {
	/** @default true */
	enabled?: boolean;
};

export type BetterAuthUrlencodedBodyParserOptions =
	UrlencodedBodyParserOptions & {
		/** @default true */
		enabled?: boolean;
	};

/**
 * Better Auth reads the raw request body of its own routes, so Nest's body
 * parser has to be turned off (`bodyParser: false` in `NestFactory.create()`).
 * These options configure the parsers this module adds back for every other
 * route.
 */
export type BetterAuthBodyParserOptions = {
	json?: BetterAuthJsonBodyParserOptions;
	urlencoded?: BetterAuthUrlencodedBodyParserOptions;
	/**
	 * Attach the raw request buffer to `req.rawBody`, for webhook signature
	 * checks. Nest's own `rawBody: true` has no effect once its body parser is
	 * off: use this instead.
	 * @default false
	 */
	rawBody?: boolean;
};

export type ResolvedJsonBodyParserOptions = JsonBodyParserOptions & {
	enabled: boolean;
	rawBody: boolean;
};

export type ResolvedUrlencodedBodyParserOptions =
	UrlencodedBodyParserOptions & {
		enabled: boolean;
	};

export type ResolvedBodyParserOptions = {
	json: ResolvedJsonBodyParserOptions;
	urlencoded: ResolvedUrlencodedBodyParserOptions;
};

export interface SkipBodyParsingMiddlewareOptions {
	/**
	 * The base path for Better Auth routes. Body parsing will be skipped for these routes.
	 * @default "/api/auth"
	 */
	basePath?: string;
	bodyParser?: ResolvedBodyParserOptions;
}
