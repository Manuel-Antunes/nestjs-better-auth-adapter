import { Injectable } from "@nestjs/common";
import { AuthenticationRegistry } from "@nestjs/authentication";
import { BetterAuthApiKeyProvider } from "nestjs-better-auth-adapter";
import { API_KEY_HEADERS } from "../create-auth.ts";

/** The apiKey() plugin's keys, read from the same headers as apiKey({ apiKeyHeaders }). */
@Injectable()
export class ApiKeyAuth extends BetterAuthApiKeyProvider {
	constructor(registry: AuthenticationRegistry) {
		super({ realm: "acme-api", headers: API_KEY_HEADERS });
		registry.registerProvider(this, { order: 2 });
	}
}
