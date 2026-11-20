import type { BetterAuthService } from "../better-auth.service.ts";

/** A `BetterAuthService` of any instance type, as the Better Auth handlers take it. */
// biome-ignore lint/suspicious/noExplicitAny: whatever instance type the app declares
export type AnyBetterAuthService = BetterAuthService<any>;
