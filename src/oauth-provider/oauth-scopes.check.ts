import {
	Inject,
	Injectable,
	type OnModuleInit,
	type Type,
} from "@nestjs/common";
import { DiscoveryService, MetadataScanner, Reflector } from "@nestjs/core";
import { BetterAuthService } from "../better-auth.service.ts";
import { BetterAuthConfigurationError } from "../errors/better-auth-configuration.error.ts";
import { OAUTH_PROVIDER_PLUGIN } from "../oauth/discovery-paths.ts";
import { findPlugin } from "../plugins.ts";
import { OAuthScopes } from "./oauth-scopes.decorator.ts";

/**
 * Fails at startup on an `@OAuthScopes()` naming a scope `oauthProvider()`
 * doesn't issue (`scopes`, or its defaults): no access token could carry
 * it, so the route would refuse them all, and a typo (`read:twin` for
 * `read:twins`) would only show as a 403 at runtime.
 */
@Injectable()
export class OAuthScopesCheck implements OnModuleInit {
	constructor(
		@Inject(DiscoveryService) private readonly discovery: DiscoveryService,
		@Inject(MetadataScanner) private readonly scanner: MetadataScanner,
		@Inject(Reflector) private readonly reflector: Reflector,
		@Inject(BetterAuthService) private readonly betterAuth: BetterAuthService,
	) {}

	onModuleInit(): void {
		// The plugin's own options, with its defaults: what it issues. Without
		// the plugin, BetterAuthOAuthProvider fails at startup itself.
		const issued = findPlugin(this.betterAuth.instance, OAUTH_PROVIDER_PLUGIN)
			?.options?.scopes;
		if (!Array.isArray(issued)) return;
		const known = new Set<unknown>(issued);

		const unknown: string[] = [];
		const check = (
			where: string,
			target: Type<unknown> | ((...args: never[]) => unknown),
		) => {
			const scopes = this.reflector.get<readonly string[] | undefined>(
				OAuthScopes,
				target,
			);
			const missing = scopes?.filter((scope) => !known.has(scope));
			if (missing?.length)
				unknown.push(`${where} (${missing.map((s) => `'${s}'`).join(", ")})`);
		};
		for (const type of this.declaringClasses()) {
			check(type.name, type);
			const prototype = type.prototype as Record<string, unknown>;
			for (const method of this.scanner.getAllMethodNames(prototype)) {
				const handler = prototype[method];
				if (typeof handler === "function")
					check(
						`${type.name}.${method}`,
						handler as (...args: never[]) => unknown,
					);
			}
		}
		if (unknown.length)
			throw new BetterAuthConfigurationError(
				`@OAuthScopes() names scopes oauthProvider() doesn't issue, which no access token could carry: ${unknown.join(", ")}. Fix the name, or add the scope to oauthProvider({ scopes }), which issues ${issued.map((s) => `'${s}'`).join(", ")}.`,
			);
	}

	/** The classes of the app's controllers and providers (resolvers, gateways). */
	private declaringClasses(): Set<Type<unknown>> {
		const types = new Set<Type<unknown>>();
		for (const wrapper of [
			...this.discovery.getControllers(),
			...this.discovery.getProviders(),
		]) {
			const { metatype } = wrapper;
			if (
				typeof metatype === "function" &&
				!wrapper.isFactory &&
				metatype.prototype
			)
				types.add(metatype as Type<unknown>);
		}
		return types;
	}
}
