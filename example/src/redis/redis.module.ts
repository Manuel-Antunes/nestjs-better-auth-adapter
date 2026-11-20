import {
	Global,
	Inject,
	Logger,
	Module,
	type OnApplicationShutdown,
} from "@nestjs/common";
import { Redis } from "ioredis";
import { ENV } from "../config/config.module.ts";
import type { Env } from "../config/env.ts";

export const REDIS = Symbol("REDIS");

/** Injects the app's `ioredis` client. */
export const InjectRedis = () => Inject(REDIS);

/**
 * The app's Redis connection, as Nest exposes a database client: a custom
 * provider, global, closed on shutdown. `ioredis` is the client Nest's own
 * Redis transport uses, and the one `@better-auth/redis-storage` takes.
 */
@Global()
@Module({
	providers: [
		{
			provide: REDIS,
			inject: [ENV],
			useFactory: async (env: Env) => {
				const logger = new Logger("Redis");
				const redis = new Redis(env.REDIS_URL, {
					lazyConnect: true,
					// While Redis is down, a command waits for two reconnections at
					// most, then fails: requests answer an error at once instead of
					// hanging (ioredis waits for 20 by default).
					maxRetriesPerRequest: 2,
				});
				// ioredis reconnects by itself; without a listener, it would print
				// each failed attempt as an unhandled error.
				redis.on("error", (error: NodeJS.ErrnoException) =>
					// Refused on IPv4 and IPv6 alike, Node's error has a code, no message.
					logger.error(
						`Redis connection error: ${error.message || error.code}`,
					),
				);
				// A Redis that can't be reached fails the boot, not the first
				// sign-in. Stops the retries too, or they'd outlive the failed boot.
				try {
					await redis.connect();
				} catch (error) {
					redis.disconnect();
					throw error;
				}
				return redis;
			},
		},
	],
	exports: [REDIS],
})
export class RedisModule implements OnApplicationShutdown {
	constructor(@InjectRedis() private readonly redis: Redis) {}

	async onApplicationShutdown() {
		await this.redis.quit();
	}
}
