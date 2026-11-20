import type { BetterAuthOptions } from "better-auth";

/** One of Better Auth's option objects, which vary by version and plugins. */
// biome-ignore lint/suspicious/noExplicitAny: Better Auth's option objects vary by version and plugins
export type ConfigObject = Record<string, any>;

/** The features whose links a Better Auth handler delivers. */
export type LinkFeature = "passwordReset" | "emailVerification" | "magicLink";

/** Better Auth's `user.validateUserInfo` gate. */
export type ValidateUserInfo = NonNullable<
	NonNullable<BetterAuthOptions["user"]>["validateUserInfo"]
>;
export type ValidateUserInfoData = Parameters<ValidateUserInfo>[0];
export type ValidateUserInfoResult = Awaited<ReturnType<ValidateUserInfo>>;

/** `validateUserInfo` as the OIDC account resolver chains it. */
export type UserInfoGate = (
	data: never,
	context: unknown,
) => Promise<{ error?: string } | undefined>;
