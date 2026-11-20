import { Redis } from "ioredis";
import { validateEnv } from "../config/env.ts";
import { createDatabase } from "../database/create-database.ts";
import { createAuth } from "./create-auth.ts";

const env = validateEnv(process.env);

/**
 * For the Better Auth CLI only, never imported by the app:
 *
 *   npx auth@latest generate --config src/auth/auth.ts
 *   npx auth@latest migrate --config src/auth/auth.ts
 *
 * (`bun run db:migrate` applies the same schema, plus the app's own tables.)
 * The CLI only reads the schema: its Redis client never connects.
 */
export const auth = createAuth({
	env,
	db: createDatabase(env.DATABASE_URL, 1),
	redis: new Redis(env.REDIS_URL, { lazyConnect: true }),
});
