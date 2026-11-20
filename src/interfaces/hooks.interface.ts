/** The models Better Auth runs database hooks for. */
export type DatabaseHookModel = "user" | "session" | "account" | "verification";

/** The operations Better Auth runs database hooks for. */
export type DatabaseHookOperation = "create" | "update" | "delete";

/** A record a database hook receives. */
// biome-ignore lint/suspicious/noExplicitAny: Better Auth's records vary by model and plugins
export type DatabaseHookData = Record<string, any>;

/** A database hook, as Better Auth's `databaseHooks` option takes it. */
// biome-ignore lint/suspicious/noExplicitAny: Better Auth decides what a database hook may return
export type DatabaseHookFn = (data: DatabaseHookData, context: any) => any;

/** A hook provider's method. */
export type HookMethod = (...args: unknown[]) => unknown;
