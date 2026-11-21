import type { BetterAuthOptions } from "better-auth";

/** The features whose links a Better Auth handler delivers. */
export type LinkFeature = "passwordReset" | "emailVerification" | "magicLink";

/** Better Auth's `user.validateUserInfo` gate. */
export type ValidateUserInfo = NonNullable<
	NonNullable<BetterAuthOptions["user"]>["validateUserInfo"]
>;
export type ValidateUserInfoData = Parameters<ValidateUserInfo>[0];
export type ValidateUserInfoResult = Awaited<ReturnType<ValidateUserInfo>>;
