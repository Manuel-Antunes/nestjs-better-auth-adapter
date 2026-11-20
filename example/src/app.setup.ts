import fastifyHelmet from "@fastify/helmet";
import {
	type INestApplication,
	type INestApplicationContext,
	ValidationPipe,
} from "@nestjs/common";
import {
	ExpressAdapter,
	type NestExpressApplication,
} from "@nestjs/platform-express";
import {
	FastifyAdapter,
	type NestFastifyApplication,
} from "@nestjs/platform-fastify";
import { IoAdapter } from "@nestjs/platform-socket.io";
import helmet from "helmet";
import type { ServerOptions } from "socket.io";
import { ENV } from "./config/config.module.ts";
import type { Env } from "./config/env.ts";

/**
 * The HTTP platform. The app (and nestjs-better-auth-adapter) behave the
 * same on both; `HTTP_ADAPTER` picks one.
 */
export function createHttpAdapter(kind: Env["HTTP_ADAPTER"]) {
	return kind === "fastify"
		? new FastifyAdapter({ trustProxy: true })
		: new ExpressAdapter();
}

/**
 * socket.io with the same origins as Better Auth's `trustedOrigins`: the
 * handshake carries the session cookie, so any other origin is refused
 * (cross-site WebSocket hijacking).
 */
class TrustedOriginsIoAdapter extends IoAdapter {
	constructor(
		app: INestApplicationContext,
		private readonly origins: string[],
	) {
		super(app);
	}

	override createIOServer(port: number, options?: ServerOptions) {
		return super.createIOServer(port, {
			...options,
			cors: { origin: this.origins, credentials: true },
		} as ServerOptions);
	}
}

/**
 * Everything `main.ts` and the e2e suites both apply, before `init()`/`listen()`.
 *
 * Nest's own body parser must be off (`bodyParser: false` in
 * `NestFactory.create()`): Better Auth reads the raw body of its routes, and
 * `BetterAuthModule` adds the parsers back for every other route.
 */
export async function setupApp(app: INestApplication) {
	const env = app.get<Env>(ENV);
	const production = env.NODE_ENV === "production";

	// The app's routes live under /api/v1. Better Auth's stay where Better
	// Auth's config puts them (/api/auth): BetterAuthModule keeps them out of
	// the global prefix.
	app.setGlobalPrefix("api/v1");
	app.useGlobalPipes(
		new ValidationPipe({
			whitelist: true,
			forbidNonWhitelisted: true,
			transform: true,
		}),
	);
	app.useWebSocketAdapter(
		new TrustedOriginsIoAdapter(app, env.TRUSTED_ORIGINS),
	);
	// The app's routes, for the same front ends: BetterAuthModule answers
	// CORS on Better Auth's routes only.
	app.enableCors({ origin: env.TRUSTED_ORIGINS, credentials: true });

	// Apollo's landing page and Better Auth's API reference load scripts from
	// CDNs: the default CSP only outside development.
	const helmetOptions = {
		contentSecurityPolicy: production ? undefined : false,
	};
	if (app.getHttpAdapter().getType() === "fastify") {
		await (app as NestFastifyApplication).register(
			fastifyHelmet,
			helmetOptions,
		);
	} else {
		const express = app as NestExpressApplication;
		express.use(helmet(helmetOptions));
		// Behind a load balancer: req.ip is the client's (Fastify: `trustProxy`).
		express.set("trust proxy", 1);
	}

	app.enableShutdownHooks();
	return app;
}
