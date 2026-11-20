import type { IncomingMessage } from "node:http";
import { Inject, type INestApplication } from "@nestjs/common";
import { CurrentUser, WsAuthenticator } from "@nestjs/authentication";
import { WsAdapter } from "@nestjs/platform-ws";
import {
	type OnGatewayConnection,
	SubscribeMessage,
	WebSocketGateway,
} from "@nestjs/websockets";
import { io as ioc, type Socket as ClientSocket } from "socket.io-client";
import type { Socket } from "socket.io";
import request from "supertest";
import WebSocket from "ws";
import { createTestApp, createTestAuth, uniqueEmail } from "../shared/app.ts";

const TRUSTED_ORIGIN = "http://app.example";
const OTHER_ORIGIN = "https://attacker.example";

/** As in Nest's docs, over socket.io: the handshake, authenticated once, then each message. */
@WebSocketGateway({ path: "/io", namespace: "orders" })
class IoOrdersGateway implements OnGatewayConnection {
	constructor(
		@Inject(WsAuthenticator) private readonly wsAuthenticator: WsAuthenticator,
	) {}

	async handleConnection(client: Socket) {
		await this.wsAuthenticator.authenticateConnection(client);
	}

	@SubscribeMessage("whoami")
	whoami(@CurrentUser("id") id: string) {
		return { event: "whoami", data: id };
	}
}

/** Nest's docs' gateway, on the `ws` adapter: the upgrade request goes to WsAuthenticator. */
@WebSocketGateway({ path: "/ws" })
class WsOrdersGateway implements OnGatewayConnection {
	constructor(
		@Inject(WsAuthenticator) private readonly wsAuthenticator: WsAuthenticator,
	) {}

	async handleConnection(client: WebSocket, request: IncomingMessage) {
		await this.wsAuthenticator.authenticateConnection(client, request);
	}

	@SubscribeMessage("whoami")
	whoami(@CurrentUser("id") id: string) {
		return { event: "whoami", data: id };
	}
}

/** A user signed up through Better Auth's route: their session cookie, and their bearer token. */
async function signUp(app: INestApplication) {
	const response = await request(app.getHttpServer())
		.post("/api/auth/sign-up/email")
		.send({ email: uniqueEmail(), password: "password-123456", name: "User" })
		.expect(200);
	const cookie = (response.headers["set-cookie"] as unknown as string[])
		.map((value) => value.split(";")[0])
		.join("; ");
	return {
		cookie,
		bearer: response.body.token as string,
		id: response.body.user.id as string,
	};
}

const closeApp = async (app: INestApplication) => {
	// Bun's http server waits for the sockets the clients leave open.
	app.getHttpServer().closeAllConnections?.();
	await app.close();
};

describe("WsAuthenticator: socket.io gateway", () => {
	let app: INestApplication;
	let url: string;
	const sockets: ClientSocket[] = [];

	beforeAll(async () => {
		({ app } = await createTestApp({
			auth: createTestAuth({ trustedOrigins: [TRUSTED_ORIGIN] }),
			controllers: [],
			providers: [IoOrdersGateway],
			listen: true,
		}));
		url = `http://localhost:${app.getHttpServer().address().port}/orders`;
	});

	afterAll(async () => {
		for (const socket of sockets) socket.disconnect();
		await closeApp(app);
	});

	const connect = (headers: Record<string, string> = {}) => {
		const socket = ioc(url, {
			path: "/io",
			transports: ["websocket"],
			extraHeaders: headers,
			reconnection: false,
		});
		sockets.push(socket);
		return socket;
	};

	/** The user the gateway sees, or `null` once it closed the connection. */
	const whoami = (socket: ClientSocket) =>
		new Promise<string | null>((resolve) => {
			socket.once("disconnect", () => resolve(null));
			socket.once("connect", () => socket.emit("whoami"));
			socket.once("whoami", resolve);
		});

	it("signs the connection in with the handshake's session cookie", async () => {
		const user = await signUp(app);
		expect(await whoami(connect({ cookie: user.cookie }))).toBe(user.id);
		expect(
			await whoami(connect({ cookie: user.cookie, origin: TRUSTED_ORIGIN })),
		).toBe(user.id);
	});

	it("disconnects a connection nobody signed in on", async () => {
		expect(await whoami(connect())).toBeNull();
	});

	it("ignores the cookie of a handshake from an origin Better Auth doesn't trust", async () => {
		const user = await signUp(app);
		expect(
			await whoami(connect({ cookie: user.cookie, origin: OTHER_ORIGIN })),
		).toBeNull();
		// A bearer token isn't sent by the browser on its own: it still counts.
		expect(
			await whoami(
				connect({
					authorization: `Bearer ${user.bearer}`,
					origin: OTHER_ORIGIN,
				}),
			),
		).toBe(user.id);
	});
});

describe("WsAuthenticator: ws gateway", () => {
	let app: INestApplication;
	let url: string;

	beforeAll(async () => {
		({ app } = await createTestApp({
			auth: createTestAuth({ trustedOrigins: [TRUSTED_ORIGIN] }),
			controllers: [],
			providers: [WsOrdersGateway],
			listen: true,
			webSocketAdapter: (nest) => new WsAdapter(nest),
		}));
		url = `ws://localhost:${app.getHttpServer().address().port}/ws`;
	});

	afterAll(async () => {
		await closeApp(app);
	});

	/** The user the gateway sees, or the close code once it closed the connection. */
	const whoami = (headers: Record<string, string> = {}) =>
		new Promise<string | number>((resolve, reject) => {
			const socket = new WebSocket(url, { headers });
			socket.once("error", reject);
			socket.once("close", (code) => resolve(code));
			socket.once("open", () =>
				// Waits for handleConnection(), which may close the connection.
				setTimeout(() => socket.send(JSON.stringify({ event: "whoami" })), 50),
			);
			socket.once("message", (data) => {
				resolve(JSON.parse(String(data)).data);
				socket.close();
			});
		});

	it("signs the connection in with the upgrade request's session cookie", async () => {
		const user = await signUp(app);
		expect(await whoami({ cookie: user.cookie })).toBe(user.id);
		expect(await whoami({ cookie: user.cookie, origin: TRUSTED_ORIGIN })).toBe(
			user.id,
		);
	});

	it("closes a connection nobody signed in on with 1008", async () => {
		expect(await whoami()).toBe(1008);
	});

	it("ignores the cookie of an upgrade from an origin Better Auth doesn't trust", async () => {
		const user = await signUp(app);
		expect(await whoami({ cookie: user.cookie, origin: OTHER_ORIGIN })).toBe(
			1008,
		);
	});
});
