import type { ExecutionContext } from "@nestjs/common";
import { BETTER_AUTH_AC_POLICY } from "../constants.ts";
import { BetterAuthConfigurationError } from "../errors/better-auth-configuration.error.ts";
import type { BetterAuthACPolicyMetadata } from "../interfaces/access-control.interface.ts";
import type { BetterAuthUser } from "../interfaces/better-auth-session.interface.ts";
import { getRequestFromContext } from "../utils.ts";
import { BetterAuthPolicy } from "./better-auth.policy.ts";
import type {
	ACPolicyResource,
	BetterAuthACPolicyClass,
	BetterAuthACPolicyConfig,
	BetterAuthOrganizationACPolicyClass,
} from "./interfaces/ac-policy.interface.ts";

/**
 * Better Auth's resource name for `resource`: the string itself, a symbol's
 * description, or a class's static `modelName`, else its name. Custom
 * mixins can apply their own naming rule and pass the result as a string.
 */
export function resourceNameOf(resource: ACPolicyResource): string {
	const name =
		typeof resource === "string"
			? resource
			: typeof resource === "symbol"
				? resource.description
				: ((resource as { modelName?: unknown }).modelName ?? resource.name);
	if (typeof name !== "string" || name === "")
		throw new BetterAuthConfigurationError(
			`Can't name the resource of a policy from ${String(resource)}: use a non-empty string, a symbol with a description, or a named class.`,
		);
	return name;
}

/** Names an action can't take: an ability by that name would replace them. */
const RESERVED = new Set([
	"before",
	"betterAuth",
	"checkPermission",
	// constructor, and BetterAuthPolicy's helpers.
	...Object.getOwnPropertyNames(BetterAuthPolicy.prototype),
]);

/**
 * The abilities of a policy: its `actions`, or every action its `statements`
 * grant, and its wildcard. Rejects names Nest never treats as abilities.
 */
function resolveActions<TRole extends string, TAction extends string>(
	resource: string,
	config: BetterAuthACPolicyConfig<TRole, TAction>,
): TAction[] {
	const actions = [
		...(config.wildcard ? [config.wildcard] : []),
		...(config.actions ??
			Object.values<readonly TAction[] | undefined>(config.statements).flatMap(
				(granted) => granted ?? [],
			)),
	];
	const unique = [...new Set(actions)];

	for (const action of unique) {
		if (RESERVED.has(action))
			throw new BetterAuthConfigurationError(
				`Action '${action}' of resource '${resource}' is reserved by @nestjs/authorization or the policy and can't be an ability name.`,
			);
	}
	return unique;
}

/**
 * Shared by the user and the organization scope: the abilities, each calling
 * `checkPermission()`, which each scope implements with its own arguments.
 */
function createPolicyBase<TRole extends string, TAction extends string>(
	scope: BetterAuthACPolicyMetadata["scope"],
	resource: string,
	config: BetterAuthACPolicyConfig<TRole, TAction>,
) {
	const actions = resolveActions(resource, config);

	abstract class AccessControlPolicy extends BetterAuthPolicy {
		/** Whether the user's role grants `action` on the resource. Guests are denied, and Nest answers 401 for them. */
		abstract checkPermission(
			user: BetterAuthUser | null,
			action: TAction,
			// biome-ignore lint/suspicious/noExplicitAny: see above
			...args: any[]
		): Promise<boolean>;
	}

	for (const action of actions) {
		Object.defineProperty(AccessControlPolicy.prototype, action, {
			value(
				this: AccessControlPolicy,
				user: BetterAuthUser | null,
				// biome-ignore lint/suspicious/noExplicitAny: see above
				...args: any[]
			) {
				return this.checkPermission(user, action, ...args);
			},
			writable: true,
			configurable: true,
		});
	}

	Reflect.defineMetadata(
		BETTER_AUTH_AC_POLICY,
		{
			scope,
			resource,
			actions,
			statements: config.statements,
			wildcard: config.wildcard,
		} satisfies BetterAuthACPolicyMetadata,
		AccessControlPolicy,
	);
	return AccessControlPolicy;
}

/**
 * Base class of a `@nestjs/authorization` policy backed by Better Auth's
 * `admin()` plugin access control. Each action becomes an ability, typed so
 * `@Can(Policy, 'create')` is checked at compile time, and the `ac` and
 * `roles` the plugin needs are built from the policy by
 * `BetterAuthAccessControl.admin()`.
 *
 * @param resource Better Auth's resource (statement key), a symbol, or a
 * class, as CASL takes them (see {@link resourceNameOf}). One policy per
 * resource and scope.
 * @param config The actions, the role statements and the wildcard.
 *
 * @example
 * ```ts
 * @Policy()
 * export class PostPolicy extends BetterAuthACPolicy<Roles, Operations>(Post, {
 *   actions: Object.values(Operations),
 *   wildcard: Operations.MANAGE,
 *   statements: { [Roles.ADMIN]: [Operations.MANAGE], [Roles.USER]: [Operations.CREATE] },
 * }) {}
 * ```
 */
export function BetterAuthACPolicy<
	const TRole extends string,
	const TAction extends string,
>(
	resource: ACPolicyResource,
	config: BetterAuthACPolicyConfig<TRole, TAction>,
): BetterAuthACPolicyClass<TAction> {
	const name = resourceNameOf(resource);

	abstract class UserACPolicy extends createPolicyBase("user", name, config) {
		async checkPermission(user: BetterAuthUser | null, action: TAction) {
			if (!user) return false;
			return this.userHasPermission(user, { [name]: [action] });
		}
	}
	return UserACPolicy as unknown as BetterAuthACPolicyClass<TAction>;
}

/**
 * Like {@link BetterAuthACPolicy}, for the `organization()` plugin: checks
 * the member's role in an organization. Policies are singletons, so the
 * organization reaches each ability as an argument: use
 * {@link activeOrganization} in `@Can()`, or pass it to `AuthorizationService`.
 */
export function BetterAuthOrganizationACPolicy<
	const TRole extends string,
	const TAction extends string,
>(
	resource: ACPolicyResource,
	config: BetterAuthACPolicyConfig<TRole, TAction>,
): BetterAuthOrganizationACPolicyClass<TAction> {
	const name = resourceNameOf(resource);

	abstract class OrganizationACPolicy extends createPolicyBase(
		"organization",
		name,
		config,
	) {
		async checkPermission(
			user: BetterAuthUser | null,
			action: TAction,
			organizationId: string | null | undefined,
		) {
			if (!user || !organizationId) return false;
			return this.memberHasPermission(user, organizationId, {
				[name]: [action],
			});
		}
	}
	return OrganizationACPolicy as unknown as BetterAuthOrganizationACPolicyClass<TAction>;
}

/**
 * `@Can()` args resolver: the active organization of the session that
 * `@nestjs/authentication`'s guard resolved.
 *
 * @example
 * ```ts
 * @Can(PostOrganizationPolicy, 'create', activeOrganization)
 * ```
 */
export const activeOrganization = async (context: ExecutionContext) => {
	const request = await getRequestFromContext(context);
	return [
		(request?.session?.activeOrganizationId as string | null | undefined) ??
			null,
	] as const;
};
