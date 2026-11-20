import swc from "unplugin-swc";
import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		globals: true,
		root: ".",
		include: ["test/**/*.e2e-spec.ts"],
		// Loads .env.test, then migrates a clean database once for the run.
		globalSetup: ["test/support/global-setup.ts"],
		setupFiles: ["test/support/setup-env.ts"],
		// Every suite shares one Postgres database.
		fileParallelism: false,
		testTimeout: 30_000,
		hookTimeout: 60_000,
	},
	plugins: [
		// esbuild (Vite's default) drops decorator metadata, which Nest's DI reads.
		swc.vite({ module: { type: "es6" } }),
	],
});
