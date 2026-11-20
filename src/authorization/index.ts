export {
	activeOrganization,
	BetterAuthACPolicy,
	BetterAuthOrganizationACPolicy,
	resourceNameOf,
} from "./ac-policy.ts";
export { BetterAuthAuthorizationModule } from "./better-auth-authorization.module.ts";
export type {
	ACPolicyResource,
	ACPolicyResourceClass,
	BetterAuthACAbilities,
	BetterAuthACPolicyClass,
	BetterAuthACPolicyConfig,
	BetterAuthOrganizationACAbilities,
	BetterAuthOrganizationACPolicyClass,
} from "./interfaces/ac-policy.interface.ts";
export type { PermissionCheck } from "./interfaces/permission-check.interface.ts";
export { BetterAuthPermissionPolicy } from "./permission.policy.ts";
