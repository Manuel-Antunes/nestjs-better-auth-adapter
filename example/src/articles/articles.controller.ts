import {
	Body,
	Controller,
	Delete,
	Get,
	HttpCode,
	Param,
	ParseUUIDPipe,
	Patch,
	Post,
} from "@nestjs/common";
import { Authenticate, CurrentUser } from "@nestjs/authentication";
import { Can } from "@nestjs/authorization";
import type { User } from "../auth/auth.types.ts";
import { ArticlePolicy } from "./article.policy.ts";
import { ArticlesService } from "./articles.service.ts";
import { CreateArticleDto, UpdateArticleDto } from "./dto/article.dto.ts";

@Controller("articles")
export class ArticlesController {
	constructor(private readonly articles: ArticlesService) {}

	/** Anyone may read; a signed-in author also sees their drafts. */
	@Get()
	@Authenticate({ optional: true })
	@Can.Anyone()
	list(@CurrentUser() viewer: User | null) {
		return this.articles.list(viewer);
	}

	@Get(":id")
	@Authenticate({ optional: true })
	@Can.Anyone()
	async get(
		@Param("id", ParseUUIDPipe) id: string,
		@CurrentUser() viewer: User | null,
	) {
		const article = await this.articles.get(id, viewer);
		return {
			...article,
			permissions: await this.articles.permissionsOn(viewer, article),
		};
	}

	/** Writing needs a verified email address (403 `email_unverified` until then). */
	@Post()
	@Authenticate({ verifiedEmail: true })
	@Can(ArticlePolicy, "create")
	create(@CurrentUser() author: User, @Body() body: CreateArticleDto) {
		return this.articles.create(author, body);
	}

	/** The record decides (author or moderator): checked in the service, after loading it. */
	@Patch(":id")
	@Can.Anyone()
	update(
		@CurrentUser() user: User,
		@Param("id", ParseUUIDPipe) id: string,
		@Body() body: UpdateArticleDto,
	) {
		return this.articles.update(user, id, body);
	}

	/** Moderators only: `publish` is granted to admins by the `manage` wildcard. */
	@Post(":id/publish")
	@Can(ArticlePolicy, "publish")
	publish(@Param("id", ParseUUIDPipe) id: string) {
		return this.articles.publish(id);
	}

	@Delete(":id")
	@HttpCode(204)
	@Can.Anyone()
	remove(@CurrentUser() user: User, @Param("id", ParseUUIDPipe) id: string) {
		return this.articles.remove(user, id);
	}
}
