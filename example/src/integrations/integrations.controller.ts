import { Controller, Get, Query } from "@nestjs/common";
import {
	ApiKeyProvider,
	type ApiKeySession,
	Authenticate,
	CurrentSession,
	CurrentUser,
} from "@nestjs/authentication";
import { Can } from "@nestjs/authorization";
import {
	BetterAuthJwtProvider,
	type BetterAuthJwtClaims,
} from "nestjs-better-auth-adapter";
import type { User } from "../auth/auth.types.ts";
import { queryParam } from "../common/can-args.ts";
import { ProjectPolicy } from "../projects/project.policy.ts";
import { ProjectsService } from "../projects/projects.service.ts";

/**
 * For scripts and third-party integrations, with an API key from the
 * `apiKey()` plugin (`x-api-key` header). Only `BetterAuthApiKeyProvider`
 * may authenticate these routes (`ApiKeyProvider` matches it): a session
 * cookie counts as no credentials. Better Auth verifies the key, its expiry
 * and its rate limit.
 */
@Controller("integrations")
@Authenticate({ providers: [ApiKeyProvider] })
export class IntegrationsController {
	constructor(private readonly projects: ProjectsService) {}

	@Get("whoami")
	@Can.Anyone()
	whoami(@CurrentUser() user: User, @CurrentSession() key: ApiKeySession) {
		return { userId: user.id, email: user.email, key };
	}

	/** The key acts as its owner: their role in the organization decides. */
	@Get("projects")
	@Can(ProjectPolicy, "read", queryParam("organizationId"))
	listProjects(@Query("organizationId") organizationId: string) {
		return this.projects.list(organizationId);
	}
}

/**
 * For the app's other services: `Authorization: Bearer <jwt>`, a token from
 * Better Auth's `jwt()` plugin (`GET /api/auth/token`), verified against its
 * JWKS. `@CurrentSession()` is the token's claims here.
 */
@Controller("internal")
@Authenticate({ providers: [BetterAuthJwtProvider] })
@Can.Anyone()
export class InternalController {
	@Get("whoami")
	whoami(
		@CurrentUser("id") userId: string,
		@CurrentSession() claims: BetterAuthJwtClaims,
	) {
		return { userId, claims };
	}
}
