import type {
	ASYNC_OPTIONS_TYPE,
	OPTIONS_TYPE,
} from "../better-auth.module-definition.ts";

/** What `forRoot()` takes: the options, and `isGlobal` (default `true`). */
export type BetterAuthModuleForRootOptions = typeof OPTIONS_TYPE;

/** What `forRootAsync()` takes: `useFactory`, `useClass` or `useExisting`, with `imports` and `inject`. */
export type BetterAuthModuleAsyncOptions = typeof ASYNC_OPTIONS_TYPE;
