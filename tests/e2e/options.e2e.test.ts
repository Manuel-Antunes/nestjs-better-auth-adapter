import {
	Body,
	Controller,
	type INestApplication,
	InternalServerErrorException,
	Post,
	Req,
} from "@nestjs/common";
import { MESSAGES } from "@nestjs/core/constants.js";
import { Public } from "@nestjs/authentication";
import request from "supertest";
import type { BetterAuthModuleOptions } from "../../src/index.ts";
import { createTestApp, createTestAuth, uniqueEmail } from "../shared/app.ts";

/** Routes that echo what the body parsers produced. */
@Public()
@Controller("test")
class BodyController {
	@Post("raw-body")
	rawBody(@Req() req: { rawBody?: Buffer }) {
		return {
			hasRawBody: !!req.rawBody,
			rawBodyType: req.rawBody ? typeof req.rawBody : null,
			isBuffer: req.rawBody instanceof Buffer,
		};
	}

	@Post("json-body")
	jsonBody(@Body() body: unknown) {
		return { hasBody: body !== undefined, body: body ?? null };
	}

	@Post("form-body")
	formBody(@Body() body: unknown) {
		return { hasBody: body !== undefined, body: body ?? null };
	}
}

describe("options e2e", () => {
	let app: INestApplication | undefined;

	afterEach(async () => {
		await app?.close();
		app = undefined;
	});

	const setup = async (module: Omit<BetterAuthModuleOptions, "auth">) => {
		({ app } = await createTestApp({
			auth: createTestAuth(),
			module,
			controllers: [BodyController],
		}));
		return app.getHttpServer();
	};

	it("should not serve any auth routes with routes: false", async () => {
		const server = await setup({ routes: false });

		const signUpResponse = await request(server)
			.post("/api/auth/sign-up/email")
			.send({
				name: "No Routes",
				email: uniqueEmail(),
				password: "password-123456",
			});
		const signInResponse = await request(server)
			.post("/api/auth/sign-in/email")
			.send({ email: uniqueEmail(), password: "password-123456" });

		expect(signUpResponse.status).toBe(404);
		expect(signInResponse.status).toBe(404);
	});

	it("should gracefully handle a middleware throwing an uncaught error", async () => {
		const error = new Error("uncaught");
		const internalError = new InternalServerErrorException(error);

		const server = await setup({
			middleware: () => {
				throw error;
			},
		});
		const response = await request(server).get("/api/auth/ok");

		expect(response.status).toBe(internalError.getStatus());
		expect(response.body).toEqual({
			statusCode: internalError.getStatus(),
			message: MESSAGES.UNKNOWN_EXCEPTION_MESSAGE,
		});
	});

	it("should run the middleware around Better Auth's handler", async () => {
		const seen: string[] = [];
		const server = await setup({
			middleware: (req, _res, next) => {
				seen.push(req.url ?? req.raw?.url);
				next();
			},
		});

		await request(server).get("/api/auth/ok").expect(200);
		expect(seen).toEqual([expect.stringContaining("/api/auth/ok")]);
	});

	it("should attach rawBody to request when bodyParser.rawBody is true", async () => {
		const server = await setup({ bodyParser: { rawBody: true } });

		const response = await request(server)
			.post("/test/raw-body")
			.send({ test: "data" });

		expect(response.status).toBe(201);
		expect(response.body).toEqual({
			hasRawBody: true,
			rawBodyType: "object",
			isBuffer: true,
		});
	});

	it("should not attach rawBody to request when rawBody is disabled", async () => {
		const server = await setup({ bodyParser: { rawBody: false } });

		const response = await request(server)
			.post("/test/raw-body")
			.send({ test: "data" });

		expect(response.status).toBe(201);
		expect(response.body).toEqual({
			hasRawBody: false,
			rawBodyType: null,
			isBuffer: false,
		});
	});

	it("should parse json and urlencoded bodies by default", async () => {
		const server = await setup({});

		const json = await request(server)
			.post("/test/json-body")
			.send({ test: "data" });
		const form = await request(server)
			.post("/test/form-body")
			.type("form")
			.send({ test: "data" });

		expect(json.body).toEqual({ hasBody: true, body: { test: "data" } });
		expect(form.body).toEqual({ hasBody: true, body: { test: "data" } });
	});

	it("should allow disabling only the json parser", async () => {
		const server = await setup({ bodyParser: { json: { enabled: false } } });

		const response = await request(server)
			.post("/test/json-body")
			.send({ test: "data" });

		expect(response.status).toBe(201);
		expect(response.body).toEqual({ hasBody: false, body: null });
	});

	it("should allow disabling only the urlencoded parser", async () => {
		const server = await setup({
			bodyParser: { urlencoded: { enabled: false } },
		});

		const response = await request(server)
			.post("/test/form-body")
			.type("form")
			.send({ test: "data" });

		expect(response.status).toBe(201);
		expect(response.body).toEqual({ hasBody: false, body: null });
	});

	it("should allow customizing the json parser limit", async () => {
		const largePayload = "x".repeat(150_000);
		const server = await setup({ bodyParser: { json: { limit: "300kb" } } });

		const response = await request(server)
			.post("/test/json-body")
			.send({ payload: largePayload });

		expect(response.status).toBe(201);
		expect(response.body).toEqual({
			hasBody: true,
			body: { payload: largePayload },
		});
	});
});
