import { Inject } from "@nestjs/common";
import type { ExecutionContext } from "@nestjs/common";
import { BetterAuthService } from "../better-auth.service.ts";
import type { BetterAuthACPolicyMetadata } from "../access-control.ts";
import { BETTER_AUTH_AC_POLICY } from "../constants.ts";
import type { BetterAuthUser } from "../types.ts";
import { getRequestFromContext } from "../utils.ts";
import { memberHasPermission } from "./organization.ts";

/**
 * A class standing for a resource, as CASL takes them: the resource is named
 * after its static `modelName` when it has one, else after the class name.
 */
// biome-ignore lint/suspicious/noExplicitAny: any constructor, whatever its parameters
export type ACPolicyResourceClass = abstract new (...args: any[]) => unknown;

/**
 * What a policy is about: Better Auth's resource name (the statement key),
 * a symbol named by its description, or a class ({@link ACPolicyResourceClass}).
 */
export type ACPolicyResource = string | symbol | ACPolicyResourceClass;

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
		throw new Error(
			`Can't name the resource of a policy from ${String(resource)}: use a non-empty string, a symbol with a description, or a named class.`,
		);
	return name;
}

/** The second argument of `BetterAuthACPolicy()` and `BetterAuthOrganizationACPolicy()`. */
export interface BetterAuthACPolicyConfig<
	TRole extends string,
	TAction extends string,
> {
	/**
	 * Every action of the resource. Required when the generics are enums, because
	 * types are erased at runtime. Defaults to the union of the actions in `statements`.
	 */
	actions?: readonly TAction[];
	/** Role → allowed actions. Becomes `ac.newRole({ [resource]: actions })` for each role. */
	statements: Partial<Record<TRole, readonly TAction[]>>;
	/**
	 * An action that expands to every action of the resource when roles are
	 * built (e.g. 'manage'). It is an action of the policy too, listed in
	 * `actions` or not.
	 */
	wildcard?: TAction;
}

/** One ability per action, typed so `@Can(Policy, 'create')` is checked at compile time. */
export type BetterAuthACAbilities<TAction extends string> = {
	// Keys are the string values, so enum members work with @Can(Policy, 'create').
	[A in TAction as `${A}`]: (user: BetterAuthUser | null) => Promise<boolean>;
};

/** Type-only: `checkPermission` is `protected` so it is not an ability of the policy. */
declare abstract class BetterAuthACPolicyBase<TAction extends string> {
	readonly betterAuth: BetterAuthService;
	protected checkPermission(
		user: BetterAuthUser | null,
		action: TAction,
	): Promise<boolean>;
}

export type BetterAuthACPolicyClass<TAction extends string> =
	abstract new () => BetterAuthACPolicyBase<TAction> &
		BetterAuthACAbilities<TAction>;

export type BetterAuthOrganizationACAbilities<TAction extends string> = {
	[A in TAction as `${A}`]: (
		user: BetterAuthUser | null,
		organizationId: string | null | undefined,
	) => Promise<boolean>;
};

/** Type-only: see {@link BetterAuthACPolicyBase}. */
declare abstract class BetterAuthOrganizationACPolicyBase<
	TAction extends string,
> {
	readonly betterAuth: BetterAuthService;
	protected checkPermission(
		user: BetterAuthUser | null,
		action: TAction,
		organizationId: string | null | undefined,
	): Promise<boolean>;
}

export type BetterAuthOrganizationACPolicyClass<TAction extends string> =
	abstract new () => BetterAuthOrganizationACPolicyBase<TAction> &
		BetterAuthOrganizationACAbilities<TAction>;

const RESERVED = new Set([
	"before",
	"constructor",
	"betterAuth",
	"checkPermission",
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
			throw new Error(
				`Action '${action}' of resource '${resource}' is reserved by @nestjs/authorization or the policy and can't be an ability name.`,
			);
	}
	return unique;
}

/** Shared by the user and the organization scope, which differ in their ability arguments. */
function createPolicyBase<TRole extends string, TAction extends string>(
	scope: BetterAuthACPolicyMetadata["scope"],
	resource: string,
	config: BetterAuthACPolicyConfig<TRole, TAction>,
	check: (
		betterAuth: BetterAuthService,
		user: BetterAuthUser,
		action: TAction,
		// biome-ignore lint/suspicious/noExplicitAny: see above
		...args: any[]
	) => Promise<boolean>,
): abstract new () => unknown {
	const actions = resolveActions(resource, config);

	abstract class AccessControlPolicy {
		// Property injection, like SessionCookieProvider's SessionService in
		// @nestjs/authentication: subclasses declare their own constructor
		// dependencies without forwarding this one.
		@Inject(BetterAuthService) readonly betterAuth!: BetterAuthService;

		async checkPermission(
			user: BetterAuthUser | null,
			action: TAction,
			// biome-ignore lint/suspicious/noExplicitAny: see above
			...args: any[]
		): Promise<boolean> {
			// Guests are denied, and Nest answers 401 for them.
			if (!user) return false;
			return check(this.betterAuth, user, action, ...args);
		}
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
	return createPolicyBase(
		"user",
		name,
		config,
		async (betterAuth, user, action) => {
			// biome-ignore lint/suspicious/noExplicitAny: the API only exists with the admin plugin
			const api = betterAuth.api as any;
			const result = await api.userHasPermission({
				body: { userId: user.id, permissions: { [name]: [action] } },
			});
			return result?.success === true;
		},
	) as unknown as BetterAuthACPolicyClass<TAction>;
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
	return createPolicyBase(
		"organization",
		name,
		config,
		async (
			betterAuth,
			user,
			action,
			organizationId: string | null | undefined,
		) => {
			if (!organizationId) return false;
			return memberHasPermission(betterAuth, user.id, organizationId, {
				[name]: [action],
			});
		},
	) as unknown as BetterAuthOrganizationACPolicyClass<TAction>;
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
