import { Policy } from "@nestjs/authorization";
import type { BetterAuthUser } from "nestjs-better-auth-adapter";
import { BetterAuthACPolicy } from "nestjs-better-auth-adapter/authorization";
import { PlatformRole } from "../authorization/enums/platform-role.enum.ts";
import type { ArticleRow } from "../database/schema/index.ts";
import { Article } from "./entities/article.entity.ts";
import { ArticleAction } from "./enums/article-action.enum.ts";

/**
 * Platform-wide abilities, checked with the admin() plugin's access control
 * against `user.role`: users write, admins publish and moderate (`manage`
 * expands to every action). Update and delete add a record-level rule on top:
 * authors always may, for their own article.
 */
@Policy()
export class ArticlePolicy extends BetterAuthACPolicy<
	PlatformRole,
	ArticleAction
>(Article, {
	actions: Object.values(ArticleAction),
	wildcard: ArticleAction.Manage,
	statements: {
		[PlatformRole.Admin]: [ArticleAction.Manage],
		[PlatformRole.User]: [ArticleAction.Create],
	},
}) {
	override update = async (user: BetterAuthUser | null, article?: ArticleRow) =>
		this.ownsOr(user, article, ArticleAction.Update);

	override delete = async (user: BetterAuthUser | null, article?: ArticleRow) =>
		this.ownsOr(user, article, ArticleAction.Delete);

	private ownsOr(
		user: BetterAuthUser | null,
		article: ArticleRow | undefined,
		action: ArticleAction,
	) {
		if (user && article?.authorId === user.id) return true;
		return this.checkPermission(user, action);
	}
}
