import { Injectable, Logger } from "@nestjs/common";
import { PasswordHasher } from "@nestjs/authentication";
import type { Redis } from "ioredis";
import {
	BetterAuthAccessControl,
	type BetterAuthModuleOptions,
	type BetterAuthOptionsFactory,
} from "nestjs-better-auth-adapter";
import { requestContextMiddleware } from "../common/request-context.ts";
import { InjectEnv } from "../config/config.module.ts";
import type { Env } from "../config/env.ts";
import type { Database } from "../database/create-database.ts";
import { InjectRedis } from "../redis/redis.module.ts";
import { InjectDrizzle } from "@nestjs/drizzle";
import { createAuth } from "./create-auth.ts";

/**
 * `BetterAuthModule.forRootAsync({ useClass: AuthConfig })`: builds the
 * Better Auth instance with what Nest injects. Everything it needs is
 * global, or a provider of `BetterAuthModule` itself
 * (`BetterAuthAccessControl`).
 */
@Injectable()
export class AuthConfig implements BetterAuthOptionsFactory {
	private readonly logger = new Logger("BetterAuth");

	constructor(
		@InjectEnv() private readonly env: Env,
		@InjectDrizzle() private readonly db: Database,
		@InjectRedis() private readonly redis: Redis,
		// Provided by AuthenticationModule: scrypt, cost from its `password` options.
		private readonly hasher: PasswordHasher,
		// Builds the admin() and organization() `ac` and `roles` from the
		// @Policy() classes; Nest knows them all before instantiating anything.
		private readonly accessControl: BetterAuthAccessControl,
	) {}

	createBetterAuthOptions(): BetterAuthModuleOptions {
		const { NODE_ENV } = this.env;
		return {
			auth: createAuth({
				env: this.env,
				db: this.db,
				redis: this.redis,
				hasher: this.hasher,
				accessControl: this.accessControl,
				logger: {
					disabled: NODE_ENV === "test",
					level: NODE_ENV === "production" ? "warn" : "info",
					log: (level, message) => {
						if (level === "error") this.logger.error(message);
						else if (level === "warn") this.logger.warn(message);
						else if (level === "debug") this.logger.debug(message);
						else this.logger.log(message);
					},
				},
			}),
			// Better Auth reads its own raw bodies; these parse the app's routes.
			bodyParser: {
				json: { limit: "1mb" },
				urlencoded: { enabled: true, extended: false },
				// req.rawBody, for the billing webhook's signature.
				rawBody: true,
			},
			// Opens the request context (request id, IP) for Better Auth's
			// routes, so its hooks can write them to the audit trail.
			middleware: requestContextMiddleware,
			// The default, spelled out: CORS on Better Auth's routes for
			// trustedOrigins (app.setup.ts enables it for the app's own).
			trustedOriginsCors: true,
		};
	}
}
