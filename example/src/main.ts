import "reflect-metadata";
import { Logger } from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import { AppModule } from "./app.module.ts";
import { createHttpAdapter, setupApp } from "./app.setup.ts";
import { validateEnv } from "./config/env.ts";

async function bootstrap() {
	const env = validateEnv(process.env);
	const app = await NestFactory.create(
		AppModule,
		createHttpAdapter(env.HTTP_ADAPTER),
		// Required by Better Auth: it parses its own request bodies.
		{ bodyParser: false, bufferLogs: true },
	);
	await setupApp(app);
	await app.listen(env.PORT, "0.0.0.0");

	const url = await app.getUrl();
	const logger = new Logger("Bootstrap");
	logger.log(`API         ${url}/api/v1 (${env.HTTP_ADAPTER})`);
	logger.log(
		`Better Auth ${url}/api/auth (reference: ${url}/api/auth/reference)`,
	);
	logger.log(`GraphQL     ${url}/graphql`);
}

await bootstrap();
