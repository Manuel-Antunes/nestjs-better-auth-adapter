import { Injectable } from "@nestjs/common";
import { APIError } from "better-auth/api";
import {
  type AuthHookContext,
  BeforeHook,
  BetterAuthService,
  Hook,
} from "nestjs-better-auth-adapter";
import type { Auth } from "../create-auth.ts";

/**
 * Better Auth's routes that need more than Better Auth asks. Better Auth
 * still decides who may call them: the session, and the `ac` and `roles`
 * `BetterAuthAccessControl` built from the policies, for `admin()` and
 * `organization()`.
 */
const SENSITIVE_ROUTES: Record<
  string,
  {
    /** The session passed a second factor (`mfaVerifiedAt`), as `@Authenticate({ mfa: true })` asks. */
    secondFactor?: boolean;
    /** The user verified their email, as `@Authenticate({ verifiedEmail: true })` asks. */
    verifiedEmail?: boolean;
  }
> = {
  // Revokes every session of the banned user.
  "/admin/ban-user": { secondFactor: true },
  "/organization/delete": { secondFactor: true },
  "/revoke-other-sessions": { secondFactor: true },
  "/api-key/create": { secondFactor: true, verifiedEmail: true },
  "/organization/invite-member": { verifiedEmail: true },
};

/**
 * What `@Authenticate({ mfa: true, verifiedEmail: true })` asks of the app's
 * routes, asked of Better Auth's own: the app serves them as they are,
 * without wrapping them in controllers of its own.
 */
@Hook()
@Injectable()
export class SensitiveRoutesHooks {
  constructor(private readonly betterAuth: BetterAuthService<Auth>) {}

  /** No path: runs before every Better Auth route, and acts on the sensitive ones. */
  @BeforeHook()
  async requireStepUp(ctx: AuthHookContext) {
    const required = ctx.path ? SENSITIVE_ROUTES[ctx.path] : undefined;
    if (!required) return;

    // The session as Nest's guard sees it, `mfa: 'verified'` included,
    // resolved once: Better Auth's endpoint reuses it.
    const signedIn = await this.betterAuth.authenticate(ctx);
    // No session: Better Auth's own check answers.
    if (!signedIn) return;

    if (required.verifiedEmail && !signedIn.user.emailVerified) {
      throw new APIError("FORBIDDEN", {
        code: "EMAIL_UNVERIFIED",
        message: "Verify your email address first.",
      });
    }
    if (required.secondFactor && signedIn.mfa !== "verified") {
      throw new APIError("UNAUTHORIZED", {
        code: "MFA_REQUIRED",
        message: "Verify a second factor first.",
      });
    }
  }
}
