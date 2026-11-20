import { Injectable } from "@nestjs/common";
import { EventEmitter2 } from "@nestjs/event-emitter";
import { APIError, isAPIError } from "better-auth/api";
import {
	AfterHook,
	type AuthHookContext,
	BeforeHook,
	BetterAuthService,
	Hook,
} from "nestjs-better-auth-adapter";
import { OrganizationRole } from "../../authorization/enums/organization-role.enum.ts";
import { AppEvent } from "../../common/enums/app-event.enum.ts";
import { type SignInFailedEvent } from "../../common/events.ts";
import { InjectEnv } from "../../config/config.module.ts";
import type { Env } from "../../config/env.ts";
import { Mailer } from "../../mail/mailer.ts";
import { templates } from "../../mail/templates.ts";

/** Throwaway inbox providers nobody may sign up with. */
const DISPOSABLE_DOMAINS = new Set([
	"mailinator.com",
	"10minutemail.com",
	"guerrillamail.com",
	"yopmail.com",
]);

/**
 * Better Auth request hooks, as a Nest provider: they run inside Better
 * Auth, through the `nestjs()` plugin, and inject what any provider can. The
 * Better Auth config declares no `hooks`.
 */
@Hook()
@Injectable()
export class AuthRequestHooks {
	constructor(
		private readonly mailer: Mailer,
		private readonly events: EventEmitter2,
		private readonly betterAuth: BetterAuthService,
		@InjectEnv() private readonly env: Env,
	) {}

	/** Refuses sign-ups from disposable inboxes, before Better Auth creates anything. */
	@BeforeHook("/sign-up/email")
	rejectDisposableEmail(ctx: AuthHookContext) {
		const email = String(ctx.body?.email ?? "");
		const domain = email.split("@").pop()?.toLowerCase() ?? "";
		if (DISPOSABLE_DOMAINS.has(domain)) {
			throw new APIError("BAD_REQUEST", {
				code: "DISPOSABLE_EMAIL",
				message: "Sign up with a permanent email address.",
			});
		}
	}

	/**
	 * An organization can't be left without its owner: transfer or delete it
	 * first. Checked before Better Auth deletes anything (a database hook on
	 * `user` would run after the sessions and accounts are gone).
	 */
	@BeforeHook("/delete-user")
	async keepOrganizationsOwned(ctx: AuthHookContext) {
		// Through the API rather than getSessionFromCtx(ctx): plugin hooks run
		// in plugin order, and bearer() may not have read the token yet.
		const session = await this.betterAuth.api.getSession({
			headers: ctx.headers ?? new Headers(),
		});
		if (session) await this.assertOwnsNoOrganization(session.user.id);
	}

	/** The same rule when an admin removes a user (`admin()` plugin). */
	@BeforeHook("/admin/remove-user")
	async keepOrganizationsOwnedByRemovedUser(ctx: AuthHookContext) {
		const userId = ctx.body?.userId;
		if (typeof userId === "string") await this.assertOwnsNoOrganization(userId);
	}

	private async assertOwnsNoOrganization(userId: string) {
		const ctx = await this.betterAuth.instance.$context;
		const owned = await ctx.adapter.count({
			model: "member",
			where: [
				{ field: "userId", value: userId },
				{ field: "role", value: OrganizationRole.Owner },
			],
		});
		if (owned > 0) {
			throw new APIError("BAD_REQUEST", {
				code: "OWNS_ORGANIZATIONS",
				message:
					"Transfer or delete the organizations you own before deleting your account.",
			});
		}
	}

	/**
	 * Sends the invitation email once the organization plugin created the
	 * invitation, instead of its `sendInvitationEmail` callback: here the
	 * mailer is injected.
	 */
	@AfterHook("/organization/invite-member")
	async sendInvitation(ctx: AuthHookContext) {
		const invitation = ctx.context.returned as
			| { id: string; email: string; organizationId: string; inviterId: string }
			| undefined;
		if (!invitation || isAPIError(invitation)) return;

		const [organization, inviter] = await Promise.all([
			ctx.context.adapter.findOne<{ name: string }>({
				model: "organization",
				where: [{ field: "id", value: invitation.organizationId }],
			}),
			ctx.context.internalAdapter.findUserById(invitation.inviterId),
		]);
		await this.mailer.send({
			to: invitation.email,
			...templates.invitation(
				this.env.APP_NAME,
				inviter?.name ?? "A teammate",
				organization?.name ?? "an organization",
				`${this.env.APP_URL}/invitations/${invitation.id}`,
			),
		});
	}

	/** No path: runs after every Better Auth route. Reports refused sign-ins to the audit trail. */
	@AfterHook()
	reportFailedSignIn(ctx: AuthHookContext) {
		const returned = ctx.context.returned;
		if (!ctx.path?.startsWith("/sign-in") || !isAPIError(returned)) return;

		this.events.emit(AppEvent.SignInFailed, {
			path: ctx.path,
			email: typeof ctx.body?.email === "string" ? ctx.body.email : null,
			reason: returned.body?.code ?? returned.message,
		} satisfies SignInFailedEvent);
		// Returning nothing keeps Better Auth's response.
	}
}
