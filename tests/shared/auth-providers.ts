import { Inject, Injectable } from "@nestjs/common";
import { AuthenticationRegistry } from "@nestjs/authentication";
import {
	BetterAuthApiKeyProvider,
	BetterAuthJwtProvider,
	BetterAuthSessionProvider,
} from "../../src/index.ts";
import type { BetterAuthPluginHost } from "../../src/index.ts";
import { hasPlugin } from "../../src/plugins.ts";

/** The app's session provider, as the README shows it. */
@Injectable()
export class SessionAuth extends BetterAuthSessionProvider {
	constructor(
		@Inject(AuthenticationRegistry) registry: AuthenticationRegistry,
	) {
		super();
		registry.registerProvider(this, { order: 0 });
	}
}

/** The app's JWT provider, as the README shows it. */
@Injectable()
export class JwtAuth extends BetterAuthJwtProvider {
	constructor(
		@Inject(AuthenticationRegistry) registry: AuthenticationRegistry,
	) {
		super();
		registry.registerProvider(this, { order: 1 });
	}
}

/** The app's API key provider, as the README shows it. */
@Injectable()
export class ApiKeyAuth extends BetterAuthApiKeyProvider {
	constructor(
		@Inject(AuthenticationRegistry) registry: AuthenticationRegistry,
	) {
		super();
		registry.registerProvider(this, { order: 2 });
	}
}

/**
 * The providers a test app registers unless it names its own: the session
 * provider, and those whose plugin `auth` has.
 */
export function defaultAuthProviders(auth: BetterAuthPluginHost) {
	return [
		SessionAuth,
		...(hasPlugin(auth, "jwt") ? [JwtAuth] : []),
		...(hasPlugin(auth, "api-key") ? [ApiKeyAuth] : []),
	];
}
