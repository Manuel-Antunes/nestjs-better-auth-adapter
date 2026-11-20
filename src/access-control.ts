import { Inject, Injectable } from "@nestjs/common";
import { DiscoveryService } from "@nestjs/core";
import {
	type AccessControl,
	type Role,
	createAccessControl,
} from "better-auth/plugins/access";
import {
	adminAc,
	defaultStatements as adminDefaultStatements,
	userAc,
} from "better-auth/plugins/admin/access";
import {
	adminAc as orgAdminAc,
	defaultStatements as orgDefaultStatements,
	memberAc,
	ownerAc,
} from "better-auth/plugins/organization/access";
import { BETTER_AUTH_AC_POLICY } from "./constants.ts";
import { BetterAuthConfigurationError } from "./errors/better-auth-configuration.error.ts";
import type {
	AccessControlDefaults,
	AccessControlScope,
	BetterAuthACPolicyMetadata,
	BetterAuthAccessControlOptions,
	BuildAccessControlOptions,
} from "./interfaces/access-control.interface.ts";

const ADMIN_DEFAULTS: AccessControlDefaults = {
	statements: adminDefaultStatements,
	roles: { admin: adminAc.statements, user: userAc.statements },
};

const ORGANIZATION_DEFAULTS: AccessControlDefaults = {
	statements: orgDefaultStatements,
	roles: {
		owner: ownerAc.statements,
		admin: orgAdminAc.statements,
		member: memberAc.statements,
	},
};

/**
 * Builds the `ac` and `roles` Better Auth's `admin()` and `organization()`
 * plugins take, from the `BetterAuthACPolicy()` / `BetterAuthOrganizationACPolicy()`
 * classes registered in the application.
 *
 * Nest scans every module, and so knows every provider's class, before it
 * instantiates anything, which is why this works inside a `forRootAsync()`
 * factory. Policies in lazily loaded modules are not seen.
 */
@Injectable()
export class BetterAuthAccessControl {
	constructor(
		@Inject(DiscoveryService) private readonly discovery: DiscoveryService,
	) {}

	/** Spread into `admin({...})`. */
	admin(
		options: BuildAccessControlOptions = {},
	): BetterAuthAccessControlOptions {
		return this.build(
			"user",
			options.defaults === false ? undefined : ADMIN_DEFAULTS,
		);
	}

	/** Spread into `organization({...})`. */
	organization(
		options: BuildAccessControlOptions = {},
	): BetterAuthAccessControlOptions {
		return this.build(
			"organization",
			options.defaults === false ? undefined : ORGANIZATION_DEFAULTS,
		);
	}

	/** Collects the discovered policies of `scope` on top of Better Auth's defaults, and builds the `ac` and `roles` from them. */
	private build(
		scope: AccessControlScope,
		base?: AccessControlDefaults,
	): BetterAuthAccessControlOptions {
		const statements: Record<string, string[]> = {};
		for (const [resource, actions] of Object.entries(base?.statements ?? {})) {
			statements[resource] = [...actions];
		}
		const grants: Record<string, Record<string, string[]>> = {};
		for (const [role, roleStatements] of Object.entries(base?.roles ?? {})) {
			grants[role] = {};
			for (const [resource, actions] of Object.entries(roleStatements)) {
				grants[role][resource] = [...actions];
			}
		}

		// Compared by class: distinct classes can share a name.
		const seen = new Map<string, { metatype: unknown; name: string }>();
		for (const { metatype } of this.discovery.getProviders()) {
			const definition =
				metatype &&
				(Reflect.getMetadata(BETTER_AUTH_AC_POLICY, metatype) as
					| BetterAuthACPolicyMetadata
					| undefined);
			if (!definition || definition.scope !== scope) continue;

			const owner = seen.get(definition.resource);
			if (owner && owner.metatype !== metatype) {
				throw new BetterAuthConfigurationError(
					`Two ${scope} policies define resource '${definition.resource}': ${owner.name} and ${metatype.name}.`,
				);
			}
			seen.set(definition.resource, { metatype, name: metatype.name });

			statements[definition.resource] = [...definition.actions];
			for (const [role, actions] of Object.entries(definition.statements)) {
				if (!actions) continue;
				const expanded =
					definition.wildcard && actions.includes(definition.wildcard)
						? definition.actions
						: actions;
				// biome-ignore lint/suspicious/noAssignInExpressions: lazily create the role's grants
				(grants[role] ??= {})[definition.resource] = [...expanded];
			}
		}

		const ac = createAccessControl(statements);
		const roles = Object.fromEntries(
			Object.entries(grants).map(([name, roleStatements]) => [
				name,
				ac.newRole(roleStatements),
			]),
		);
		return { ac: ac as AccessControl, roles: roles as Record<string, Role> };
	}
}
