import type { INestApplication } from "@nestjs/common";
import { io as ioc, type Socket as ClientSocket } from "socket.io-client";
import {
	createTestApp,
	createTestAuth,
	signUp,
	TestGateway,
	type TestAuth,
} from "../shared/app.ts";

/** The next `event` the socket receives. */
function next<T = unknown>(socket: ClientSocket, event: string) {
	return new Promise<T>((resolve) => socket.once(event, resolve));
}

describe("websocket auth e2e", () => {
	let app: INestApplication;
	let auth: TestAuth;
	let socket: ClientSocket | undefined;
	let url: string;

	/** A connected client of the `test` namespace, sending `token` as a Bearer header. */
	const connect = async (token?: string | null) => {
		socket = ioc(url, {
			path: "/ws",
			...(token && { extraHeaders: { Authorization: `Bearer ${token}` } }),
		});
		await next(socket, "connect");
		return socket;
	};

	beforeAll(async () => {
		auth = createTestAuth();
		({ app } = await createTestApp({
			auth,
			providers: [TestGateway],
			listen: true,
		}));
		url = `http://localhost:${app.getHttpServer().address().port}/test`;
	});

	afterAll(async () => {
		// Bun's http server waits for the sockets socket.io leaves open.
		app.getHttpServer().closeAllConnections?.();
		await app.close();
	});

	afterEach(() => {
		socket?.disconnect();
		socket = undefined;
	});

	it("should allow anonymous access to a public event", async () => {
		const client = await connect();
		const reply = next(client, "anonymous");
		client.emit("anonymous");

		expect(await reply).toBe("hello");
	});

	it("should reject unauthenticated access to a protected event", async () => {
		const client = await connect();
		const exception = next<{
			status: string;
			statusCode: number;
			message: string;
		}>(client, "exception");
		client.emit("protected");

		expect(await exception).toMatchObject({
			status: "error",
			statusCode: 401,
			message: "Unauthorized",
		});
	});

	it("should allow authenticated access to a protected event", async () => {
		const { token, user } = await signUp(auth);
		const client = await connect(token);
		const reply = next(client, "protected");
		client.emit("protected");

		expect(await reply).toBe(user.name);
	});

	it("should allow anonymous access to an optional event", async () => {
		const client = await connect();
		const reply = next(client, "optional");
		client.emit("optional");

		expect(await reply).toBeNull();
	});

	it("should allow authenticated access to an optional event", async () => {
		const { token, user } = await signUp(auth);
		const client = await connect(token);
		const reply = next(client, "optional");
		client.emit("optional");

		expect(await reply).toBe(user.name);
	});

	it("should reject a protected event with an invalid token", async () => {
		const client = await connect("invalid-token");
		const exception = next<{
			status: string;
			statusCode: number;
			message: string;
		}>(client, "exception");
		client.emit("protected");

		expect(await exception).toMatchObject({
			status: "error",
			statusCode: 401,
			message: "Unauthorized",
		});
	});
});
