import { Global, Inject, Module } from "@nestjs/common";
import { validateEnv } from "./env.ts";

export const ENV = Symbol("ENV");

/** Injects the validated, typed environment (`Env`). */
export const InjectEnv = () => Inject(ENV);

/** Validates the environment once, at startup: a bad value fails the boot. */
@Global()
@Module({
	providers: [{ provide: ENV, useFactory: () => validateEnv(process.env) }],
	exports: [ENV],
})
export class ConfigModule {}
