import { drizzle } from "drizzle-orm/node-postgres";
import * as schema from "./schema/index.ts";

/**
 * The options of node-postgres's `drizzle()`: one connection pool, shared by
 * Better Auth (through its Drizzle adapter) and the app's repositories.
 * `DrizzleModule` builds the app's database from them (see `AppModule`);
 * the Better Auth CLI and the migration script, which run without Nest,
 * call {@link createDatabase}.
 */
export function databaseOptions(connectionString: string, max = 10) {
	return { connection: { connectionString, max }, schema };
}

/** The same database, outside Nest: close it with `db.$client.end()`. */
export function createDatabase(connectionString: string, max = 10) {
	return drizzle(databaseOptions(connectionString, max));
}

/** What `@InjectDrizzle()` injects. */
export type Database = ReturnType<typeof createDatabase>;
