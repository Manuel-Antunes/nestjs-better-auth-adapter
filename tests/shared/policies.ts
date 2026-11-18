import { Injectable } from "@nestjs/common";
import { Policy } from "@nestjs/authorization";
import {
	type ACPolicyResourceClass,
	BetterAuthACPolicy,
	type BetterAuthACPolicyConfig,
	BetterAuthOrganizationACPolicy,
} from "../../src/authorization/index.ts";
import type { BetterAuthUser } from "../../src/index.ts";

export enum Roles {
	OWNER = "owner",
	ADMIN = "admin",
	MEMBER = "member",
	USER = "user",
}

export enum Operations {
	MANAGE = "manage",
	CREATE = "create",
	UPDATE = "update",
}

export class Post {
	id!: string;
	authorId!: string;
}

/**
 * A custom mixin, as an app would write one: resources are classes named in
 * lower case, `MANAGE` is the wildcard, and admins manage every resource.
 */
export function AppPolicy<const TAction extends Operations>(
	resource: ACPolicyResourceClass,
	config: Omit<BetterAuthACPolicyConfig<Roles, TAction>, "wildcard">,
) {
	return BetterAuthACPolicy<Roles, TAction | Operations.MANAGE>(
		resource.name.toLowerCase(),
		{
			...config,
			wildcard: Operations.MANAGE,
			statements: { [Roles.ADMIN]: [Operations.MANAGE], ...config.statements },
		},
	);
}

/** User-scope policy for the `post` resource, with a record-level override of `update`. */
@Policy()
export class PostPolicy extends AppPolicy(Post, {
	actions: [Operations.CREATE, Operations.UPDATE],
	statements: { [Roles.USER]: [Operations.CREATE] },
}) {
	// Authors may always edit their own posts; everyone else needs the 'update' permission.
	override update = async (user: BetterAuthUser | null, post?: Post) => {
		if (user && post?.authorId === user.id) return true;
		return this.checkPermission(user, Operations.UPDATE);
	};
}

/** Organization-scope policy for the `post` resource. */
@Policy()
export class PostOrganizationPolicy extends BetterAuthOrganizationACPolicy<
	Roles,
	Operations
>("post", {
	actions: Object.values(Operations),
	wildcard: Operations.MANAGE,
	statements: {
		[Roles.OWNER]: [Operations.MANAGE],
		[Roles.ADMIN]: [Operations.MANAGE],
		[Roles.MEMBER]: [Operations.CREATE],
	},
}) {}

/** A policy that declares its own constructor dependency next to the mixin's. */
@Injectable()
export class Clock {
	now() {
		return 1;
	}
}

/** Policy with its own constructor dependency next to the mixin's. */
@Policy()
export class ReportPolicy extends BetterAuthACPolicy<Roles, "read">("report", {
	statements: { [Roles.ADMIN]: ["read"] },
}) {
	constructor(readonly clock: Clock) {
		super();
	}
}
