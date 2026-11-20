import { existsSync } from "node:fs";

// Variables already set (HTTP_ADAPTER from the test:* scripts, CI's
// DATABASE_URL) win over the file.
if (existsSync(".env.test")) process.loadEnvFile(".env.test");
