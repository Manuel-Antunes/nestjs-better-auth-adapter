import { UsePipes, ValidationPipe } from "@nestjs/common";
import { CurrentUser, WsAuthenticator } from "@nestjs/authentication";
import { Can } from "@nestjs/authorization";
import { OnEvent } from "@nestjs/event-emitter";
import {
	ConnectedSocket,
	MessageBody,
	type OnGatewayConnection,
	SubscribeMessage,
	WebSocketGateway,
	WebSocketServer,
} from "@nestjs/websockets";
import { IsString } from "class-validator";
import type { Namespace, Socket } from "socket.io";
import type { User } from "../auth/auth.types.ts";
import { messageField } from "../common/can-args.ts";
import { AppEvent } from "../common/enums/app-event.enum.ts";
import { type ProjectCreatedEvent } from "../common/events.ts";
import { ProjectPolicy } from "./project.policy.ts";

class SubscribeDto {
	@IsString()
	organizationId!: string;
}

const room = (organizationId: string) => `organization:${organizationId}`;

/**
 * Live project updates over socket.io (`/realtime` namespace). Clients send
 * the session cookie, or `Authorization: Bearer <session token>` (bearer()
 * plugin), in the handshake.
 *
 * - Nest runs no guard on `handleConnection()`: `WsAuthenticator`
 *   authenticates the handshake, and disconnects it when nobody signed in.
 *   A handshake's cookie from an origin Better Auth doesn't trust counts as
 *   none (cross-site WebSocket hijacking).
 * - `AuthenticationModule`'s guard and `@Can()` then cover each message like
 *   a route, so a session revoked mid-connection stops working.
 */
@WebSocketGateway({ namespace: "realtime" })
@UsePipes(new ValidationPipe({ whitelist: true }))
export class ProjectsGateway implements OnGatewayConnection {
	@WebSocketServer()
	private readonly server!: Namespace;

	constructor(private readonly wsAuthenticator: WsAuthenticator) {}

	async handleConnection(client: Socket) {
		// socket.io: WsAuthenticator reads the handshake's headers itself.
		await this.wsAuthenticator.authenticateConnection(client);
	}

	/** Joins an organization's room: members who may read its projects only. */
	@SubscribeMessage("projects.subscribe")
	@Can(ProjectPolicy, "read", messageField("organizationId"))
	async subscribe(
		@MessageBody() body: SubscribeDto,
		@ConnectedSocket() client: Socket,
		@CurrentUser() user: User,
	) {
		await client.join(room(body.organizationId));
		return {
			event: "projects.subscribed",
			data: { organizationId: body.organizationId, userId: user.id },
		};
	}

	@OnEvent(AppEvent.ProjectCreated)
	broadcast(event: ProjectCreatedEvent) {
		this.server.to(room(event.organizationId)).emit("project.created", event);
	}
}
