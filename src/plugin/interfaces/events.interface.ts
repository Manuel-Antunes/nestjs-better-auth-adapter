import type { AuthenticationEvent } from "@nestjs/authentication";
import type { AuthHookContext } from "./bridge.interface.ts";

/** A session an event names. */
export interface EventSession {
	userId: string;
	sessionId: string;
	token: string;
}

/** What a request's before hook read for its events, before the endpoint changed it. */
export interface EventSnapshot {
	/** The sessions the request ends. */
	sessions?: EventSession[];
	/** The user the request is about. */
	userId?: string;
}

/** Publishes a request's events, once its endpoint ran. */
export type EventPublisher = (
	ctx: AuthHookContext,
	emit: (event: AuthenticationEvent) => void,
) => Promise<void> | void;
