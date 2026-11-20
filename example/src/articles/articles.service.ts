import { Injectable, NotFoundException } from "@nestjs/common";
import { AuthorizationService } from "@nestjs/authorization";
import { and, desc, eq, or, type SQL } from "drizzle-orm";
import type { User } from "../auth/auth.types.ts";
import type { Database } from "../database/create-database.ts";
import { InjectDrizzle } from "@nestjs/drizzle";
import { articles } from "../database/schema/index.ts";
import { ArticlePolicy } from "./article.policy.ts";
import type { CreateArticleDto, UpdateArticleDto } from "./dto/article.dto.ts";

@Injectable()
export class ArticlesService {
	constructor(
		@InjectDrizzle() private readonly db: Database,
		private readonly authorization: AuthorizationService,
	) {}

	/** Published articles, plus the viewer's own drafts. */
	list(viewer: User | null) {
		return this.db
			.select()
			.from(articles)
			.where(this.visibleTo(viewer))
			.orderBy(desc(articles.createdAt));
	}

	async get(id: string, viewer: User | null) {
		const [article] = await this.db
			.select()
			.from(articles)
			.where(and(eq(articles.id, id), this.visibleTo(viewer)));
		if (!article) throw new NotFoundException("Article not found");
		return article;
	}

	async create(author: User, input: CreateArticleDto) {
		const [article] = await this.db
			.insert(articles)
			.values({ ...input, authorId: author.id })
			.returning();
		return article;
	}

	/**
	 * Loads the record first, then asks the policy about it: a missing article
	 * is a 404, someone else's a 403 (`authorize()` throws, and Nest's
	 * authorization module turns that into the same answer as `@Can()`).
	 */
	async update(user: User, id: string, input: UpdateArticleDto) {
		const article = await this.get(id, user);
		await this.authorization.authorize(ArticlePolicy, "update", user, article);
		const [updated] = await this.db
			.update(articles)
			.set(input)
			.where(eq(articles.id, id))
			.returning();
		return updated;
	}

	async publish(id: string) {
		const [article] = await this.db
			.update(articles)
			.set({ status: "published", publishedAt: new Date() })
			.where(eq(articles.id, id))
			.returning();
		if (!article) throw new NotFoundException("Article not found");
		return article;
	}

	async remove(user: User, id: string) {
		const article = await this.get(id, user);
		await this.authorization.authorize(ArticlePolicy, "delete", user, article);
		await this.db.delete(articles).where(eq(articles.id, id));
	}

	/** What each article response says the viewer may do, for the UI. */
	async permissionsOn(
		user: User | null,
		article: typeof articles.$inferSelect,
	) {
		const [canUpdate, canDelete] = await Promise.all([
			this.authorization.can(ArticlePolicy, "update", user, article),
			this.authorization.can(ArticlePolicy, "delete", user, article),
		]);
		return { canUpdate, canDelete };
	}

	private visibleTo(viewer: User | null): SQL | undefined {
		const published = eq(articles.status, "published");
		return viewer ? or(published, eq(articles.authorId, viewer.id)) : published;
	}
}
