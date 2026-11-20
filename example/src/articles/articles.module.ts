import { Module } from "@nestjs/common";
import { ArticlePolicy } from "./article.policy.ts";
import { ArticlesController } from "./articles.controller.ts";
import { ArticlesService } from "./articles.service.ts";

@Module({
	controllers: [ArticlesController],
	providers: [ArticlesService, ArticlePolicy],
})
export class ArticlesModule {}
