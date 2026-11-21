import {
	ApiKeyProvider,
	type ApiKeySession,
	type AuthenticationResult,
} from "@nestjs/authentication";
import {
	type ExecutionContext,
	Inject,
	Logger,
	type OnModuleInit,
} from "@nestjs/common";
import { BetterAuthService } from "../better-auth.service.ts";
import { BetterAuthApiKeyError } from "../errors/better-auth-api-key.error.ts";
import { BetterAuthConfigurationError } from "../errors/better-auth-configuration.error.ts";
import { OwnedByBetterAuthError } from "../errors/owned-by-better-auth.error.ts";
import type { BetterAuthApiKey } from "../interfaces/better-auth-api-key.interface.ts";
import type { BetterAuthApiKeyProviderOptions } from "../interfaces/better-auth-providers.interface.ts";
import type { AnyBetterAuthService } from "../interfaces/better-auth-service.interface.ts";
import type { BetterAuthUser } from "../interfaces/better-auth-session.interface.ts";
import { hasPlugin } from "../plugins.ts";
import { assertNotBanned, checksBans } from "./banned-user.ts";

/** What `verifyApiKey` answers. */
interface VerifiedApiKey {
	valid?: boolean;
	error?: { message?: string };
	key?: BetterAuthApiKey | null;
}

/**
 * Base class for the keys of Better Auth's `apiKey()` plugin. Extend it and
 * register it, as Nest's `ApiKeyProvider`; `BetterAuthService` is
 * property-injected:
 *
 * ```ts
 * @Injectable()
 * export class ApiKeyAuth extends BetterAuthApiKeyProvider {
 *   constructor(registry: AuthenticationRegistry) {
 *     super({ headers: 'x-api-key' });
 *     registry.registerProvider(this, { order: 2 });
 *   }
 * }
 * ```
 *
 * Better Auth owns the key format and how keys are hashed and stored, so this
 * extends `ApiKeyProvider` (for `@Authenticate({ providers: [ApiKeyProvider] })`
 * and `instanceof` checks) but delegates the whole check to `verifyApiKey`:
 * its rate limits, remaining counts and key permissions still apply. Nest's
 * `findKey()` and `generate()` throw; {@link validate} maps a verified key
 * to its user.
 *
 * Leave `enableSessionForAPIKeys` off: otherwise `getSession()` turns a key
 * into a regular session and `BetterAuthSessionProvider` accepts it first.
 */
export abstract class BetterAuthApiKeyProvider
	extends ApiKeyProvider<BetterAuthUser>
	implements OnModuleInit
{
	@Inject(BetterAuthService) protected readonly betterAuth!: BetterAuthService;
	protected readonly logger = new Logger(BetterAuthApiKeyProvider.name);
	private readonly headerNames: string[];
	private readonly apiRealm: string;
	#checkOrganizations?: boolean;
	#checkBans?: boolean;

	constructor(options: BetterAuthApiKeyProviderOptions = {}) {
		const realm = options.realm ?? "api";
		// The prefix is unused: authenticate() is overridden.
		super({ prefix: "ba", realm });
		this.apiRealm = realm;

		// The api-key plugin doesn't expose its options: its `apiKeyHeaders`
		// are repeated here.
		const headers = options.headers ?? "x-api-key";
		this.headerNames = (Array.isArray(headers) ? headers : [headers]).map(
			(name) => name.toLowerCase(),
		);
	}

	/**
	 * Fails at startup without the `apiKey()` plugin. A subclass's own
	 * `onModuleInit()` calls `super.onModuleInit()`.
	 */
	onModuleInit(): void {
		if (!hasPlugin(this.betterAuth.instance, "api-key"))
			throw new BetterAuthConfigurationError(
				`${this.constructor.name} verifies the keys of Better Auth's apiKey() plugin: add it to betterAuth({ plugins }), from '@better-auth/api-key'.`,
			);
	}

	override async authenticate(
		context: ExecutionContext,
	): Promise<AuthenticationResult<BetterAuthUser, ApiKeySession> | null> {
		const key = await this.apiKey(context);
		if (!key) return null;

		// biome-ignore lint/suspicious/noExplicitAny: the API only exists with the api-key plugin
		const api = this.betterAuth.api as any;
		const verified = await this.verifyApiKey(api, key);
		const { valid, error, key: record } = verified;
		if (!valid || !record) {
			throw this.invalid(error?.message);
		}

		const user = await this.validate(record);
		if (!user) throw this.invalid("API key refused by validate()");
		this.#checkBans ??= checksBans(this.betterAuth.instance);
		if (this.#checkBans) assertNotBanned(user);

		return {
			user: user,
			session: {
				method: "api-key",
				keyId: record.id,
				...(record.expiresAt && { expiresAt: new Date(record.expiresAt) }),
			},
		};
	}

	/**
	 * The key a call presents, else `undefined` (no credentials): by default
	 * the first of the `headers` given to `super()`, read with `header()`.
	 * Override it to read keys elsewhere (another transport, a query
	 * parameter...), or override `header()` to keep the same headers.
	 */
	protected apiKey(
		context: ExecutionContext,
	): string | undefined | Promise<string | undefined> {
		return this.headerNames
			.map((name) => this.header(context, name))
			.find(Boolean);
	}

	/**
	 * The user a key Better Auth verified signs in: its owner, or `null` (or
	 * a thrown `AuthenticationError`) to refuse it. Override it to add checks
	 * (the key's `metadata`, `permissions`...), and call `super.validate()` to
	 * keep these. Users the `admin()` plugin banned are refused after it,
	 * whatever it returns.
	 */
	protected async validate(
		record: BetterAuthApiKey,
	): Promise<BetterAuthUser | null> {
		// Only user-owned keys sign in. The key record doesn't say what its
		// `referenceId` refers to (that is in the plugin's configuration, which
		// it doesn't expose), so an organization's key, whose id could match a
		// user's with serial ids, is told apart by looking the id up, along
		// with the user.
		const ownerId = record.referenceId ?? record.userId;
		if (!ownerId) throw this.invalid("API key is not owned by a user");
		const auth = this.betterAuth.instance;
		const ctx = await auth.$context;
		this.#checkOrganizations ??= hasPlugin(auth, "organization");
		const [organization, user] = await Promise.all([
			this.#checkOrganizations
				? ctx.adapter.findOne({
						model: "organization",
						where: [{ field: "id", value: ownerId }],
						select: ["id"],
					})
				: null,
			ctx.internalAdapter.findUserById(ownerId),
		]);
		if (organization) throw this.invalid("API key is owned by an organization");
		if (!user) throw this.invalid("API key owner not found");
		return user as BetterAuthUser;
	}

	private async verifyApiKey(
		api: AnyBetterAuthService["api"],
		key: string,
	): Promise<VerifiedApiKey> {
		let verified: VerifiedApiKey;
		try {
			verified = await api.verifyApiKey({ body: { key } });
		} catch (error) {
			// Some versions throw for a bad key. (verifyApiKey answers a store
			// outage with `valid: false` itself, so that is a 401 too.)
			const status = (error as { statusCode?: number })?.statusCode;
			if (typeof status === "number" && status >= 400 && status < 500) {
				throw this.invalid((error as Error).message);
			}
			throw error;
		}
		return verified;
	}

	// Better Auth looks keys up itself; this provider never reaches findKey().
	protected findKey(): never {
		throw new OwnedByBetterAuthError(
			"BetterAuthApiKeyProvider delegates verification to Better Auth.",
		);
	}

	/** Keys are created with Better Auth's `createApiKey()`: it owns the key format. */
	override generate(): never {
		throw new OwnedByBetterAuthError(
			"Create keys with BetterAuthService.api.createApiKey(): Better Auth owns the key format.",
		);
	}

	/** `WWW-Authenticate` challenge sent with a 401 when no provider found credentials. */
	override challenge(): string {
		return `ApiKey realm="${this.apiRealm}"`;
	}

	/**
	 * One generic message for the client, so it can't tell an expired key from
	 * a disabled or rate limited one. The reason goes to the server's logs.
	 */
	protected invalid(reason?: string): BetterAuthApiKeyError {
		if (reason) this.logger.debug(`API key refused: ${reason}`);
		return new BetterAuthApiKeyError(this.challenge());
	}
}
