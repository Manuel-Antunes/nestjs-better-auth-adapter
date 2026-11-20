import { Module } from "@nestjs/common";
import { ApolloDriver, type ApolloDriverConfig } from "@nestjs/apollo";
import { DrizzleModule } from "@nestjs/drizzle";
import { EventEmitterModule } from "@nestjs/event-emitter";
import { GraphQLModule } from "@nestjs/graphql";
import { drizzle } from "drizzle-orm/node-postgres";
import { AccountModule } from "./account/account.module.ts";
import { ArticlesModule } from "./articles/articles.module.ts";
import { AuditModule } from "./audit/audit.module.ts";
import { AuthModule } from "./auth/auth.module.ts";
import { BillingModule } from "./billing/billing.module.ts";
import { CommonModule } from "./common/common.module.ts";
import { ConfigModule, ENV } from "./config/config.module.ts";
import type { Env } from "./config/env.ts";
import { databaseOptions } from "./database/create-database.ts";
import { IntegrationsModule } from "./integrations/integrations.module.ts";
import { MailModule } from "./mail/mail.module.ts";
import { MetaModule } from "./meta/meta.module.ts";
import { ProjectsModule } from "./projects/projects.module.ts";
import { RedisModule } from "./redis/redis.module.ts";

@Module({
	imports: [
		// Infrastructure, global.
		ConfigModule,
		EventEmitterModule.forRoot(),
		// Postgres, through Nest's Drizzle module: @InjectDrizzle() anywhere, and
		// the pool closed on shutdown. Better Auth's tables are in it too.
		DrizzleModule.forRootAsync({
			inject: [ENV],
			useFactory: (env: Env) => ({
				drizzle,
				...databaseOptions(env.DATABASE_URL),
			}),
		}),
		// Better Auth's secondary storage (see createAuth).
		RedisModule,
		CommonModule,
		MailModule,
		AuditModule,

		// Authentication and authorization (Better Auth behind Nest's ports).
		AuthModule,

		// GraphQL on /graphql. The context must be built per request, so the
		// authentication guard finds the request (and its cookies) in it.
		GraphQLModule.forRoot<ApolloDriverConfig>({
			driver: ApolloDriver,
			path: "/graphql",
			autoSchemaFile: true,
			sortSchema: true,
			context: ({ req, res }: { req: unknown; res: unknown }) => ({ req, res }),
		}),

		// Features.
		MetaModule,
		AccountModule,
		ArticlesModule,
		ProjectsModule,
		BillingModule,
		IntegrationsModule,
	],
})
export class AppModule {}
