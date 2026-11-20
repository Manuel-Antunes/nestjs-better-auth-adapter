import { io, type Socket } from "socket.io-client";
import { createTestApp, type TestApp } from "./support/test-app.ts";
import {
	createOrganization,
	signUpVerified,
	type TestUser,
} from "./support/users.ts";

/** The next `event` the socket receives. */
const next = <T>(socket: Socket, event: string) =>
	new Promise<T>((resolve) => socket.once(event, resolve));

describe("GraphQL and WebSockets: the same guards and policies as REST", () => {
	let t: TestApp;
	let owner: TestUser;
	let outsider: TestUser;
	let organizationId: string;
	const sockets: Socket[] = [];

	beforeAll(async () => {
		t = await createTestApp({ listen: true });
		owner = await signUpVerified(t, { name: "Gina GraphQL" });
		outsider = await signUpVerified(t);
		({ id: organizationId } = await createOrganization(t, owner, "Hooli"));
	});
	afterAll(async () => {
		for (const socket of sockets) socket.disconnect();
		await t.app.close();
	});

	const graphql = (query: string, variables: object, user?: TestUser) => {
		const req = t
			.http()
			.post("/graphql")
			.set("content-type", "application/json");
		if (user) req.set("Authorization", user.bearer);
		return req.send({ query, variables });
	};

	describe("GraphQL", () => {
		it("@Authenticate({ optional: true }): the viewer, or null", async () => {
			const query = "{ viewer { id name emailVerified } }";
			const anonymous = await graphql(query, {}).expect(200);
			expect(anonymous.body.data.viewer).toBeNull();

			const signedIn = await graphql(query, {}, owner).expect(200);
			expect(signedIn.body.data.viewer).toEqual({
				id: owner.id,
				name: "Gina GraphQL",
				emailVerified: true,
			});
		});

		it("@Can() with activeOrganization and with a GraphQL argument", async () => {
			const created = await graphql(
				"mutation ($input: CreateProjectDto!) { createProject(input: $input) { id name } }",
				{ input: { name: "From GraphQL" } },
				owner,
			).expect(200);
			expect(created.body.data.createProject.name).toBe("From GraphQL");

			const listQuery =
				"query ($id: ID!) { projects(organizationId: $id) { name } }";
			const listed = await graphql(
				listQuery,
				{ id: organizationId },
				owner,
			).expect(200);
			expect(listed.body.data.projects).toEqual([{ name: "From GraphQL" }]);

			const denied = await graphql(listQuery, { id: organizationId }, outsider);
			expect(denied.body.errors[0].extensions.code).toBe("FORBIDDEN");
		});
	});

	describe("socket.io", () => {
		const connect = async (
			user?: TestUser,
			origin = "http://localhost:5173",
		) => {
			const socket = io(`${t.url}/realtime`, {
				transports: ["websocket"],
				extraHeaders: {
					origin,
					...(user && { Authorization: user.bearer }),
				},
			});
			sockets.push(socket);
			await next(socket, "connect");
			return socket;
		};

		it("authenticates each message from the handshake's bearer token, and checks @Can() on it", async () => {
			const socket = await connect(owner);
			const subscribed = next<{ organizationId: string; userId: string }>(
				socket,
				"projects.subscribed",
			);
			socket.emit("projects.subscribe", { organizationId });
			expect(await subscribed).toEqual({ organizationId, userId: owner.id });

			// Broadcasts of the room reach the subscriber.
			const broadcast = next<{ name: string }>(socket, "project.created");
			await t
				.http()
				.post("/api/v1/projects")
				.set("Authorization", owner.bearer)
				.send({ name: "Live" })
				.expect(201);
			expect((await broadcast).name).toBe("Live");
		});

		it("refuses non-members with @Can()", async () => {
			const socket = await connect(outsider);
			const error = next<{ status: string; message: string }>(
				socket,
				"exception",
			);
			socket.emit("projects.subscribe", { organizationId });
			expect((await error).status).toBe("error");
		});

		it("disconnects anonymous clients at the handshake (WsAuthenticator)", async () => {
			const socket = io(`${t.url}/realtime`, {
				transports: ["websocket"],
				extraHeaders: { origin: "http://localhost:5173" },
				reconnection: false,
			});
			sockets.push(socket);
			expect(await next<string>(socket, "disconnect")).toBe(
				"io server disconnect",
			);
		});
	});
});
