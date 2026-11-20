import { Injectable } from "@nestjs/common";
import { AuthenticationRegistry } from "@nestjs/authentication";
import { BetterAuthJwtProvider } from "nestjs-better-auth-adapter";

/** The jwt() plugin's JWTs, for the integrations (see IntegrationsController). */
@Injectable()
export class JwtAuth extends BetterAuthJwtProvider {
	constructor(registry: AuthenticationRegistry) {
		super({ realm: "acme-api" });
		registry.registerProvider(this, { order: 1 });
	}
}
