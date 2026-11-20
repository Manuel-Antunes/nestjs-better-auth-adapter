import type { BetterAuthUser } from "../../interfaces/better-auth-session.interface.ts";
import type { BetterAuthPolicy } from "../better-auth.policy.ts";

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
export declare abstract class BetterAuthACPolicyBase<
	TAction extends string,
> extends BetterAuthPolicy {
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
export declare abstract class BetterAuthOrganizationACPolicyBase<
	TAction extends string,
> extends BetterAuthPolicy {
	protected checkPermission(
		user: BetterAuthUser | null,
		action: TAction,
		organizationId: string | null | undefined,
	): Promise<boolean>;
}

export type BetterAuthOrganizationACPolicyClass<TAction extends string> =
	abstract new () => BetterAuthOrganizationACPolicyBase<TAction> &
		BetterAuthOrganizationACAbilities<TAction>;
