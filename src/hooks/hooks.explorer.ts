import { Inject, Injectable, type OnModuleInit } from "@nestjs/common";
import { DiscoveryService, MetadataScanner } from "@nestjs/core";
import { createAuthMiddleware } from "better-auth/api";
import { BETTER_AUTH_MODULE_OPTIONS } from "../better-auth.module-definition.ts";
import type { BetterAuthModuleOptions } from "../interfaces/better-auth-module-options.interface.ts";
import {
	AFTER_DATABASE_HOOK_KEY,
	AFTER_HOOK_KEY,
	BEFORE_DATABASE_HOOK_KEY,
	BEFORE_HOOK_KEY,
	DATABASE_HOOK_KEY,
	HOOK_KEY,
} from "../constants.ts";
import { bridgeOf } from "../plugins.ts";
import { NEST_OWNED } from "../plugin/bridge.ts";
import type {
	DatabaseHookModel,
	DatabaseHookOperation,
	HookMethod as Method,
} from "../interfaces/hooks.interface.ts";
import { addDatabaseHook } from "./database-hooks.ts";

/**
 * Finds the `@Hook()` and `@DatabaseHook()` providers once Nest has created
 * them, and runs their methods inside Better Auth through the `nestjs()`
 * plugin.
 */
@Injectable()
export class BetterAuthHooksExplorer implements OnModuleInit {
	constructor(
		@Inject(BETTER_AUTH_MODULE_OPTIONS)
		private readonly options: BetterAuthModuleOptions,
		@Inject(DiscoveryService) private readonly discovery: DiscoveryService,
		@Inject(MetadataScanner) private readonly scanner: MetadataScanner,
	) {}

	onModuleInit(): void {
		for (const { instance, metatype } of this.discovery.getProviders()) {
			if (!instance || !metatype) continue;
			const isHook = Reflect.getMetadata(HOOK_KEY, metatype);
			const isDatabaseHook = Reflect.getMetadata(DATABASE_HOOK_KEY, metatype);
			if (!isHook && !isDatabaseHook) continue;

			const prototype = Object.getPrototypeOf(instance);
			for (const name of this.scanner.getAllMethodNames(prototype)) {
				const method = prototype[name] as Method;
				if (isHook) this.addRequestHooks(instance, method);
				if (isDatabaseHook) this.addDatabaseHooks(instance, method);
			}
		}
	}

	private addRequestHooks(instance: object, method: Method): void {
		for (const [key, type] of [
			[BEFORE_HOOK_KEY, "before"],
			[AFTER_HOOK_KEY, "after"],
		] as const) {
			if (!Reflect.hasMetadata(key, method)) continue;
			const path: string | undefined = Reflect.getMetadata(key, method);

			bridgeOf(this.options.auth).hooks[type].push(
				Object.assign(
					{
						matcher: (ctx: { path?: string }) => !path || ctx.path === path,
						handler: createAuthMiddleware(async (ctx) =>
							method.call(instance, ctx),
						),
					},
					{ [NEST_OWNED]: true },
				),
			);
		}
	}

	private addDatabaseHooks(instance: object, method: Method): void {
		for (const [key, type] of [
			[BEFORE_DATABASE_HOOK_KEY, "before"],
			[AFTER_DATABASE_HOOK_KEY, "after"],
		] as const) {
			if (!Reflect.hasMetadata(key, method)) continue;
			const { model, operation } = Reflect.getMetadata(key, method) as {
				model: DatabaseHookModel;
				operation: DatabaseHookOperation;
			};

			addDatabaseHook(
				bridgeOf(this.options.auth),
				model,
				operation,
				type,
				(data, context) => method.call(instance, data, context),
			);
		}
	}
}
