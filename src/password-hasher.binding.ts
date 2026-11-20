import {
	Inject,
	Injectable,
	type OnModuleInit,
	Optional,
} from "@nestjs/common";
import { PasswordHasher } from "@nestjs/authentication";
import { BETTER_AUTH_MODULE_OPTIONS } from "./better-auth.module-definition.ts";
import type { BetterAuthModuleOptions } from "./interfaces/better-auth-module-options.interface.ts";
import { BetterAuthConfigurationError } from "./errors/better-auth-configuration.error.ts";
import type { BetterAuthPassword } from "./plugin/interfaces/password.interface.ts";
import { BIND_PASSWORD_HASHER } from "./plugin/password.constants.ts";

/**
 * Binds a `nestPasswordHasher()` placeholder, which Better Auth copied when
 * the instance was created, to Nest's `PasswordHasher` once Nest has it.
 */
@Injectable()
export class BetterAuthPasswordHasherBinding implements OnModuleInit {
	constructor(
		@Inject(BETTER_AUTH_MODULE_OPTIONS)
		private readonly options: BetterAuthModuleOptions,
		@Optional()
		@Inject(PasswordHasher)
		private readonly hasher?: PasswordHasher,
	) {}

	onModuleInit(): void {
		const password = this.options.auth.options.emailAndPassword?.password as
			| BetterAuthPassword
			| undefined;
		const bind = password?.[BIND_PASSWORD_HASHER];
		if (!bind) return;
		if (!this.hasher)
			throw new BetterAuthConfigurationError(
				"nestPasswordHasher() needs Nest's PasswordHasher: import AuthenticationModule from '@nestjs/authentication'.",
			);
		bind(this.hasher);
	}
}
