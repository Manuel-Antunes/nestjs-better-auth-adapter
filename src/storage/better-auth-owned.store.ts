import { Inject, Injectable, Optional } from "@nestjs/common";
import {
	AUTHENTICATION_MODULE_OPTIONS,
	AuthenticationStorage,
	type AuthenticationModuleOptions,
	type AuthenticationStorageSources,
	type EmailTokenStore,
	type MagicLinkStore,
	type OidcStateStore,
	type SessionStore,
} from "@nestjs/authentication";
import { OwnedByBetterAuthError } from "../errors/owned-by-better-auth.error.ts";

const refused = OwnedByBetterAuthError.store;

/**
 * `@nestjs/authentication`'s stores for what Better Auth owns: sessions,
 * password reset and verification links, magic links, social sign-ins in
 * progress. Every call throws.
 *
 * The `passwordReset`, `emailVerification`, `magicLink` and `oidc`
 * features, with Better Auth handlers, name these stores: in production Nest refuses to
 * start on its in-memory defaults, and those would run a second, volatile
 * auth system next to Better Auth's. Registered from the constructor, for
 * the features configured only, and not `sessions` when Nest's own
 * `session` feature is on (that one needs a real store).
 */
@Injectable()
export class BetterAuthOwnedStore
	implements SessionStore, EmailTokenStore, MagicLinkStore, OidcStateStore
{
	constructor(
		@Inject(AuthenticationStorage) storage: AuthenticationStorage,
		@Optional()
		@Inject(AUTHENTICATION_MODULE_OPTIONS)
		options?: AuthenticationModuleOptions,
	) {
		const sources: AuthenticationStorageSources = {};
		if (
			(options?.passwordReset || options?.magicLink || options?.oidc) &&
			!options.session
		)
			sources.sessions = this;
		if (options?.passwordReset || options?.emailVerification)
			sources.emailTokens = this;
		if (options?.magicLink) sources.magicLinks = this;
		if (options?.oidc) sources.oidcStates = this;
		if (Object.keys(sources).length > 0) storage.registerSource(sources);
	}

	getSession(): never {
		throw refused("SessionStore", "getSession", "sessions");
	}
	createSession(): never {
		throw refused("SessionStore", "createSession", "sessions");
	}
	touchSession(): never {
		throw refused("SessionStore", "touchSession", "sessions");
	}
	deleteSession(): never {
		throw refused("SessionStore", "deleteSession", "sessions");
	}
	listUserSessions(): never {
		throw refused("SessionStore", "listUserSessions", "sessions");
	}
	deleteUserSessions(): never {
		throw refused("SessionStore", "deleteUserSessions", "sessions");
	}

	saveEmailToken(): never {
		throw refused("EmailTokenStore", "saveEmailToken", "email links");
	}
	consumeEmailToken(): never {
		throw refused("EmailTokenStore", "consumeEmailToken", "email links");
	}
	deleteUserEmailTokens(): never {
		throw refused("EmailTokenStore", "deleteUserEmailTokens", "email links");
	}

	saveMagicLink(): never {
		throw refused("MagicLinkStore", "saveMagicLink", "magic links");
	}
	consumeMagicLink(): never {
		throw refused("MagicLinkStore", "consumeMagicLink", "magic links");
	}

	saveOidcState(): never {
		throw refused("OidcStateStore", "saveOidcState", "social sign-ins");
	}
	consumeOidcState(): never {
		throw refused("OidcStateStore", "consumeOidcState", "social sign-ins");
	}
}
