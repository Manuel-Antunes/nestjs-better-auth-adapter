import "./setup-env.ts";
import { Redis } from "ioredis";
import pg from "pg";
import { migrate } from "../../src/database/migrate.ts";

/**
 * Once per run: a clean test database, migrated with the same SQL as
 * production (`drizzle/`), Better Auth's tables included, and an empty
 * Redis database for Better Auth's secondary storage.
 */
export default async function globalSetup() {
	const url = process.env.DATABASE_URL;
	if (!url?.includes("test")) {
		throw new Error(
			`Refusing to reset ${url}: the e2e suites need a database whose name contains "test".`,
		);
	}

	const client = new pg.Client({ connectionString: url });
	await client.connect();
	try {
		await client.query("drop schema if exists public cascade");
		await client.query("drop schema if exists drizzle cascade");
		await client.query("create schema public");
	} finally {
		await client.end();
	}
	await migrate(url);
	await flushRedis(process.env.REDIS_URL);
}

/** Empties the test's Redis database: one of its own, never the default 0. */
async function flushRedis(url: string | undefined) {
	const db = url ? Number(new URL(url).pathname.slice(1) || 0) : 0;
	if (!url || !(db > 0)) {
		throw new Error(
			`Refusing to flush ${url}: the e2e suites need a Redis database of their own, like redis://localhost:6380/1.`,
		);
	}
	const redis = new Redis(url);
	try {
		await redis.flushdb();
	} finally {
		await redis.quit();
	}
}
