import { z } from "zod";

/** A comma-separated list, as environment variables carry them. */
const list = z
	.string()
	.default("")
	.transform((value) =>
		value
			.split(",")
			.map((item) => item.trim())
			.filter(Boolean),
	);

const optional = z
	.string()
	.optional()
	.transform((value) => value || undefined);

/**
 * Every setting the app reads, validated once at startup: a missing secret
 * fails the boot, not the first sign-in. Imports nothing from Nest, so the
 * Better Auth CLI's config file and the migration script can use it too.
 */
export const envSchema = z.object({
	NODE_ENV: z
		.enum(["development", "test", "production"])
		.default("development"),
	PORT: z.coerce.number().int().positive().default(3000),
	HTTP_ADAPTER: z.enum(["express", "fastify"]).default("express"),
	APP_NAME: z.string().default("Acme"),
	APP_URL: z.url(),

	DATABASE_URL: z.url(),
	// Better Auth's secondary storage: sessions, rate limits, single-use tokens.
	REDIS_URL: z.url(),

	BETTER_AUTH_SECRET: z.string().min(32),
	BETTER_AUTH_URL: z.url(),
	TRUSTED_ORIGINS: list,

	SMTP_URL: z.url(),
	MAIL_FROM: z.string().min(1),

	PASSWORD_HASH_LOG_N: z.coerce.number().int().min(10).max(22).default(17),

	GITHUB_CLIENT_ID: optional,
	GITHUB_CLIENT_SECRET: optional,
	GOOGLE_CLIENT_ID: optional,
	GOOGLE_CLIENT_SECRET: optional,

	BILLING_WEBHOOK_SECRET: z.string().min(16),
});

export type Env = z.infer<typeof envSchema>;

/** `ConfigModule.forRoot({ validate })`, and the scripts that run outside Nest. */
export function validateEnv(config: Record<string, unknown>): Env {
	const result = envSchema.safeParse(config);
	if (!result.success) {
		throw new Error(
			`Invalid environment variables:\n${z.prettifyError(result.error)}`,
		);
	}
	return result.data;
}
