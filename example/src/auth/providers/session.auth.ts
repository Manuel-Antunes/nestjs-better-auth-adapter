import { Injectable } from "@nestjs/common";
import { AuthenticationRegistry } from "@nestjs/authentication";
import { BetterAuthSessionProvider } from "nestjs-better-auth-adapter";

/** Better Auth's session cookie (and Bearer session token): first in the chain. */
@Injectable()
export class SessionAuth extends BetterAuthSessionProvider {
	constructor(registry: AuthenticationRegistry) {
		super();
		registry.registerProvider(this, { order: 0 });
	}
}
