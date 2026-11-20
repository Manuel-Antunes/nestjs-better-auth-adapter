import type { INestApplication } from "@nestjs/common";
import { getDrizzleToken } from "@nestjs/drizzle";
import { Test } from "@nestjs/testing";
import type { Redis } from "ioredis";
import { BetterAuthService } from "nestjs-better-auth-adapter";
import request from "supertest";
import { AppModule } from "../../src/app.module.ts";
import { createHttpAdapter, setupApp } from "../../src/app.setup.ts";
import type { Auth } from "../../src/auth/create-auth.ts";
import type { Database } from "../../src/database/create-database.ts";
import { Mailer } from "../../src/mail/mailer.ts";
import { REDIS } from "../../src/redis/redis.module.ts";
import { InMemoryMailer } from "./in-memory.mailer.ts";

export const adapter =
	process.env.HTTP_ADAPTER === "fastify" ? "fastify" : "express";

export interface TestApp {
	app: INestApplication;
	http: () => ReturnType<typeof request>;
	mailer: InMemoryMailer;
	auth: Auth;
	db: Database;
	/** Better Auth's secondary storage. */
	redis: Redis;
	/** The listening URL, with `listen: true`. */
	url?: string;
}

/**
 * The real `AppModule`, on the adapter under test, with one change: emails
 * go to an in-memory outbox instead of SMTP.
 */
export async function createTestApp({ listen = false } = {}): Promise<TestApp> {
	const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
		.overrideProvider(Mailer)
		.useClass(InMemoryMailer)
		.compile();

	const app = moduleRef.createNestApplication(createHttpAdapter(adapter), {
		bodyParser: false,
		logger: ["error"],
	});
	await setupApp(app);

	let url: string | undefined;
	if (listen) {
		await app.listen(0, "127.0.0.1");
		url = (await app.getUrl()).replace("[::1]", "127.0.0.1");
	} else {
		await app.init();
		if (adapter === "fastify") {
			await app.getHttpAdapter().getInstance().ready();
		}
	}

	return {
		app,
		url,
		http: () => request(app.getHttpServer()),
		mailer: app.get(Mailer) as InMemoryMailer,
		auth: app.get(BetterAuthService<Auth>).instance,
		db: app.get<Database>(getDrizzleToken()),
		redis: app.get<Redis>(REDIS),
	};
}
