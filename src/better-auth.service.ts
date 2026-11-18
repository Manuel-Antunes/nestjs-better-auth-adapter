import { Inject, Injectable } from "@nestjs/common";
import type { Auth } from "better-auth";
import {
	BETTER_AUTH_MODULE_OPTIONS,
	type BetterAuthModuleOptions,
} from "./better-auth.module-definition.ts";

/**
 * The Better Auth instance, injectable. Pass your instance's type to get the
 * plugin endpoints typed:
 *
 * @example
 * ```ts
 * constructor(private readonly betterAuth: BetterAuthService<typeof auth>) {}
 * ```
 */
@Injectable()
export class BetterAuthService<T extends { api: T["api"] } = Auth> {
	constructor(
		@Inject(BETTER_AUTH_MODULE_OPTIONS)
		private readonly options: BetterAuthModuleOptions<T>,
	) {}

	/** Better Auth's server-side API: `auth.api`. */
	get api(): T["api"] {
		return this.options.auth.api;
	}

	/** The whole Better Auth instance. */
	get instance(): T {
		return this.options.auth;
	}
}
