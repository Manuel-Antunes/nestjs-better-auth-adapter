/**
 * Compile-time checks of the policy mixins, run by `bun run typecheck`
 * (`tsc`): an `expectTypeOf` that doesn't hold, or a `@ts-expect-error`
 * line that compiles, fails it.
 */
import { Can } from "@nestjs/authorization";
import { expectTypeOf } from "vitest";
import type { BetterAuthUser } from "../../src/index.ts";
import {
	type ACPolicyResource,
	BetterAuthACPolicy,
	type BetterAuthACPolicyConfig,
	BetterAuthOrganizationACPolicy,
	resourceNameOf,
} from "../../src/authorization/index.ts";
import { AppPolicy, Operations, Roles } from "../shared/policies.ts";

type Ability = (user: BetterAuthUser | null) => Promise<boolean>;
type OrganizationAbility = (
	user: BetterAuthUser | null,
	organizationId: string | null | undefined,
) => Promise<boolean>;

class Comment {}
class Article {}

// ── The resource: a string, a symbol or a class ────────────────────────────

BetterAuthACPolicy("post", { statements: { admin: ["read"] } });
BetterAuthACPolicy(Symbol("post"), { statements: { admin: ["read"] } });
BetterAuthACPolicy(Comment, { statements: { admin: ["read"] } });
BetterAuthOrganizationACPolicy(Comment, { statements: { owner: ["read"] } });

// @ts-expect-error a number is not a resource
BetterAuthACPolicy(1, { statements: { admin: ["read"] } });
// @ts-expect-error an object that can't be constructed is not a resource class
BetterAuthACPolicy({ name: "post" }, { statements: { admin: ["read"] } });
// @ts-expect-error the config is required
BetterAuthACPolicy("post");
// @ts-expect-error the single-object signature is gone
BetterAuthACPolicy({ resource: "post", statements: { admin: ["read"] } });
// @ts-expect-error statements are required
BetterAuthOrganizationACPolicy("post", { actions: ["read"] });

// ── Actions and roles inferred from the config ─────────────────────────────

const Inferred = BetterAuthACPolicy("doc", {
	wildcard: "manage",
	statements: { admin: ["manage"], editor: ["read", "write"] },
});
type InferredPolicy = InstanceType<typeof Inferred>;
expectTypeOf<InferredPolicy["read"]>().toEqualTypeOf<Ability>();
expectTypeOf<InferredPolicy["write"]>().toEqualTypeOf<Ability>();
expectTypeOf<InferredPolicy["manage"]>().toEqualTypeOf<Ability>();
expectTypeOf<InferredPolicy>().not.toHaveProperty("delete");

// ── Roles and actions given as enums ───────────────────────────────────────

const Explicit = BetterAuthACPolicy<Roles, Operations>("post", {
	actions: Object.values(Operations),
	wildcard: Operations.MANAGE,
	statements: {
		[Roles.ADMIN]: [Operations.MANAGE],
		[Roles.USER]: [Operations.CREATE],
	},
});
type ExplicitPolicy = InstanceType<typeof Explicit>;
expectTypeOf<ExplicitPolicy["create"]>().toEqualTypeOf<Ability>();
expectTypeOf<ExplicitPolicy["update"]>().toEqualTypeOf<Ability>();
expectTypeOf<ExplicitPolicy["manage"]>().toEqualTypeOf<Ability>();

BetterAuthACPolicy<Roles, Operations>("post", {
	// @ts-expect-error not one of the roles
	statements: { guest: [Operations.CREATE] },
});
BetterAuthACPolicy<Roles, Operations>("post", {
	// @ts-expect-error not one of the actions
	statements: { [Roles.ADMIN]: ["delete"] },
});
BetterAuthACPolicy<Roles, Operations>("post", {
	// @ts-expect-error the wildcard is one of the actions
	wildcard: "everything",
	statements: {},
});
BetterAuthACPolicy<Roles, Operations>("post", {
	// @ts-expect-error `actions` lists actions of the policy only
	actions: ["publish"],
	statements: {},
});

// ── @Can() sees exactly the abilities ──────────────────────────────────────

class PostPolicy extends Explicit {}
Can(PostPolicy, "create");
Can(PostPolicy, Operations.UPDATE);
Can(PostPolicy, "manage");
// @ts-expect-error not an ability of the policy
Can(PostPolicy, "delete");
// @ts-expect-error checkPermission is protected, not an ability
Can(PostPolicy, "checkPermission");

declare const postPolicy: PostPolicy;
// @ts-expect-error checkPermission is protected
postPolicy.checkPermission(null, Operations.CREATE);

// An ability can be overridden, and fall back to the permission check.
class OwnPostPolicy extends Explicit {
	override update = async (user: BetterAuthUser | null, authorId?: string) =>
		(!!user && user.id === authorId) ||
		this.checkPermission(user, Operations.UPDATE);
}
Can(OwnPostPolicy, "update");

export class WrongCheckPolicy extends Explicit {
	read = async (user: BetterAuthUser | null) =>
		// @ts-expect-error checkPermission takes the policy's actions only
		this.checkPermission(user, "read");
}

// ── Organization scope: abilities take the organization ────────────────────

class TeamPolicy extends BetterAuthOrganizationACPolicy<Roles, "invite">(
	"team",
	{ statements: { [Roles.OWNER]: ["invite"] } },
) {}
expectTypeOf<TeamPolicy["invite"]>().toEqualTypeOf<OrganizationAbility>();
Can(TeamPolicy, "invite", () => ["organization-id"] as const);
// @ts-expect-error the organization comes from a resolver
Can(TeamPolicy, "invite");
// @ts-expect-error the resolver returns the organization id
Can(TeamPolicy, "invite", () => [42] as const);

// ── A custom mixin: classes named in lower case, a fixed wildcard ──────────
// (`AppPolicy` in tests/shared/policies.ts)

class ArticlePolicy extends AppPolicy(Article, {
	actions: [Operations.CREATE],
	statements: { [Roles.USER]: [Operations.CREATE] },
}) {}
expectTypeOf<ArticlePolicy["create"]>().toEqualTypeOf<Ability>();
expectTypeOf<ArticlePolicy["manage"]>().toEqualTypeOf<Ability>();
expectTypeOf<ArticlePolicy>().not.toHaveProperty("update");
Can(ArticlePolicy, "manage");
// @ts-expect-error not an ability of this policy
Can(ArticlePolicy, "update");

// @ts-expect-error this mixin takes classes only
AppPolicy("article", { statements: {} });
AppPolicy(Article, {
	// @ts-expect-error actions are Operations
	statements: { [Roles.USER]: ["publish"] },
});
AppPolicy(Article, {
	// @ts-expect-error roles are Roles
	statements: { guest: [Operations.CREATE] },
});
AppPolicy(Article, {
	// @ts-expect-error the mixin owns the wildcard
	wildcard: Operations.CREATE,
	statements: {},
});

// ── A mixin factory with a naming strategy, for any resource ───────────────

function createPolicyMixin<TRole extends string>(
	name: (resource: ACPolicyResource) => string,
) {
	return <const TAction extends string>(
		resource: ACPolicyResource,
		config: BetterAuthACPolicyConfig<TRole, TAction>,
	) => BetterAuthACPolicy<TRole, TAction>(name(resource), config);
}
const KebabPolicy = createPolicyMixin<Roles>((resource) =>
	resourceNameOf(resource)
		.replace(/([a-z])([A-Z])/g, "$1-$2")
		.toLowerCase(),
);

class BlogPostPolicy extends KebabPolicy(Article, {
	statements: { [Roles.ADMIN]: ["archive", "publish"] },
}) {}
expectTypeOf<BlogPostPolicy["archive"]>().toEqualTypeOf<Ability>();
expectTypeOf<BlogPostPolicy["publish"]>().toEqualTypeOf<Ability>();
Can(BlogPostPolicy, "publish");
// @ts-expect-error not an ability of this policy
Can(BlogPostPolicy, "delete");
KebabPolicy(Article, {
	// @ts-expect-error the factory fixed the roles
	statements: { guest: ["read"] },
});

// ── Organization scope, inferred from the config (README example) ──────────

class Project {}
class ProjectPolicy extends BetterAuthOrganizationACPolicy(Project, {
	statements: { owner: ["create", "delete"], member: ["create"] },
}) {}
expectTypeOf<ProjectPolicy["create"]>().toEqualTypeOf<OrganizationAbility>();
expectTypeOf<ProjectPolicy["delete"]>().toEqualTypeOf<OrganizationAbility>();
expectTypeOf<ProjectPolicy>().not.toHaveProperty("update");
Can(ProjectPolicy, "delete", () => ["organization-id"] as const);
