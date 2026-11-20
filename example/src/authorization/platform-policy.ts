import {
	type ACPolicyResource,
	type ACPolicyResourceClass,
	BetterAuthACPolicy,
	type BetterAuthACPolicyConfig,
	resourceNameOf,
} from "nestjs-better-auth-adapter/authorization";
import { PlatformRole } from "./enums/platform-role.enum.ts";

/** `AuditLog` → `audit-log`: Better Auth's resource names, from any resource. */
export function kebabResourceName(resource: ACPolicyResource): string {
	return resourceNameOf(resource)
		.replace(/([a-z0-9])([A-Z])/g, "$1-$2")
		.toLowerCase();
}

/** The wildcard of every platform policy: it expands to all the resource's actions. */
export const MANAGE = "manage";

/**
 * The app's own policy mixin, for platform-wide (`admin()` plugin) resources:
 *
 * - resources are classes, named in kebab case (`AuditLog` → `audit-log`);
 * - roles are {@link PlatformRole}s only;
 * - `manage` is always the wildcard, and admins always manage everything.
 *
 * It stays as typed as `BetterAuthACPolicy()`: `@Can(Policy, 'typo')`, a role
 * outside `PlatformRole` or a `wildcard` of one's own don't compile.
 */
export function PlatformPolicy<const TAction extends string>(
	resource: ACPolicyResourceClass,
	config: Omit<BetterAuthACPolicyConfig<PlatformRole, TAction>, "wildcard">,
) {
	return BetterAuthACPolicy<PlatformRole, TAction | typeof MANAGE>(
		kebabResourceName(resource),
		{
			...config,
			wildcard: MANAGE,
			statements: { [PlatformRole.Admin]: [MANAGE], ...config.statements },
		},
	);
}
