import {
	Inject,
	Injectable,
	type OnModuleInit,
	Optional,
} from "@nestjs/common";
import { AuthenticationEvents } from "@nestjs/authentication";
import { BETTER_AUTH_MODULE_OPTIONS } from "./better-auth.module-definition.ts";
import type { BetterAuthModuleOptions } from "./interfaces/better-auth-module-options.interface.ts";
import { addEventDatabaseHooks } from "./plugin/events.ts";
import { bridgeOf } from "./plugins.ts";

/**
 * Points the `nestjs()` plugin's events at Nest's `AuthenticationEvents`,
 * so Better Auth's sign-ins, sign-outs, second-factor changes, password
 * resets and email verifications reach `events$` and the diagnostics
 * channels, as Nest's own services publish theirs. `BetterAuthModule` takes
 * it out when the app closes (`resetBridge()`).
 */
@Injectable()
export class BetterAuthEventsBinding implements OnModuleInit {
	constructor(
		@Inject(BETTER_AUTH_MODULE_OPTIONS)
		private readonly options: BetterAuthModuleOptions,
		@Optional()
		@Inject(AuthenticationEvents)
		private readonly events?: AuthenticationEvents,
	) {}

	onModuleInit(): void {
		const bridge = bridgeOf(this.options.auth);
		const events = this.events;
		if (!bridge.events || !events) return;
		bridge.emit = (event) => events.emit(event);
		addEventDatabaseHooks(bridge);
	}
}
