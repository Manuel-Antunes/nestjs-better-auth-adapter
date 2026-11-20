import { defineBuildConfig } from "unbuild";

export default defineBuildConfig({
	declaration: true,
	entries: [
		"src/index",
		"src/plugin/index",
		"src/authorization/index",
		"src/oauth-provider/index",
	],
	rollup: {
		emitCJS: false,
		esbuild: {
			tsconfigRaw: {
				compilerOptions: {
					experimentalDecorators: true,
				},
			},
		},
	},
});
