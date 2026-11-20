import { ConfigurableModuleBuilder } from "@nestjs/common";
import type { BetterAuthModuleOptions } from "./interfaces/better-auth-module-options.interface.ts";

export const BETTER_AUTH_MODULE_OPTIONS = Symbol.for(
	"nestjs-better-auth-adapter:module-options",
);

export const {
	ConfigurableModuleClass,
	OPTIONS_TYPE,
	ASYNC_OPTIONS_TYPE,
	MODULE_OPTIONS_TOKEN,
} = new ConfigurableModuleBuilder<BetterAuthModuleOptions>({
	optionsInjectionToken: BETTER_AUTH_MODULE_OPTIONS,
})
	.setClassMethodName("forRoot")
	.setFactoryMethodName("createBetterAuthOptions")
	.setExtras({ isGlobal: true }, (definition, extras) => ({
		...definition,
		global: extras.isGlobal,
	}))
	.build();
