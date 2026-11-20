import { fileURLToPath, pathToFileURL } from "node:url";
import { migrate as runMigrations } from "drizzle-orm/node-postgres/migrator";
import { createDatabase } from "./create-database.ts";

/** The SQL migrations `drizzle-kit generate` writes: Better Auth's tables and the app's, in one history. */
export const MIGRATIONS_FOLDER = fileURLToPath(
	new URL("../../drizzle", import.meta.url),
);

/**
 * Applies the pending migrations. `bun run db:migrate` (drizzle-kit) does the
 * same from the command line; this one is for code: the e2e setup, or a
 * container that migrates before it starts.
 */
export async function migrate(databaseUrl: string) {
	const db = createDatabase(databaseUrl, 1);
	try {
		await runMigrations(db, { migrationsFolder: MIGRATIONS_FOLDER });
	} finally {
		await db.$client.end();
	}
}

// Run as a script: `node src/database/migrate.ts`.
if (
	process.argv[1] &&
	import.meta.url === pathToFileURL(process.argv[1]).href
) {
	const url = process.env.DATABASE_URL;
	if (!url) throw new Error("DATABASE_URL is not set.");
	await migrate(url);
}
