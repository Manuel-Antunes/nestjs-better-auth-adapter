import { Controller, Get } from "@nestjs/common";
import { Public } from "@nestjs/authentication";
import { InjectDrizzle } from "@nestjs/drizzle";
import { sql } from "drizzle-orm";
import type { Redis } from "ioredis";
import {
	BetterAuthService,
	findPlugin,
	hasPlugin,
} from "nestjs-better-auth-adapter";
import type { BetterAuthOptions } from "better-auth";
import type { Auth } from "../auth/create-auth.ts";
import type { Database } from "../database/create-database.ts";
import { InjectRedis } from "../redis/redis.module.ts";

/** Public routes: no provider runs, `@CurrentUser()` would be `null`. */
@Controller()
@Public()
export class MetaController {
	constructor(
		private readonly betterAuth: BetterAuthService<Auth>,
		@InjectDrizzle() private readonly db: Database,
		@InjectRedis() private readonly redis: Redis,
	) {}

	/**
	 * For load balancers: the app is up, and reaches its database and Redis,
	 * where Better Auth keeps the sessions.
	 */
	@Get("health")
	async health() {
		await Promise.all([this.db.execute(sql`select 1`), this.redis.ping()]);
		return { status: "ok" };
	}

	/**
	 * What a sign-in page needs to know, read from the Better Auth instance
	 * (`hasPlugin`/`findPlugin`), so the frontend never drifts from the config.
	 */
	@Get("auth/methods")
	methods() {
		const auth = this.betterAuth.instance;
		const options: BetterAuthOptions = auth.options;
		// Where BetterAuthModule serves Better Auth: BETTER_AUTH_URL's path, if
		// it has one, wins over options.basePath, as in Better Auth itself.
		const { basePath } = this.betterAuth;
		return {
			basePath,
			emailAndPassword: !!options.emailAndPassword?.enabled,
			magicLink: hasPlugin(auth, "magic-link"),
			twoFactor: hasPlugin(auth, "two-factor"),
			organizations: hasPlugin(auth, "organization"),
			social: Object.keys(options.socialProviders ?? {}),
			jwks: findPlugin(auth, "jwt") ? `${basePath}/jwks` : null,
			apiKeys: hasPlugin(auth, "api-key"),
		};
	}
}
