/**
 * Domain events, emitted with `@nestjs/event-emitter`. Better Auth's hooks
 * emit them and return: mail and the audit trail react on their own, so a
 * slow SMTP server never slows down a sign-up.
 */
export interface UserEvent {
	userId: string;
	email: string;
	name: string;
}

/** The user as stored after an update: role and ban changes end up in the audit trail. */
export interface UserUpdatedEvent {
	userId: string;
	role: string | null;
	banned: boolean;
	emailVerified: boolean;
}

export interface SessionCreatedEvent {
	userId: string;
	sessionId: string;
	ipAddress: string | null;
	userAgent: string | null;
}

export interface AccountLinkedEvent {
	userId: string;
	providerId: string;
}

export interface SignInFailedEvent {
	path: string;
	email: string | null;
	reason: string;
}

export interface ProjectCreatedEvent {
	organizationId: string;
	projectId: string;
	name: string;
	createdBy: string;
}

export interface BillingChangedEvent {
	organizationId: string;
	actorId: string | null;
	plan: string;
	status: string;
}
