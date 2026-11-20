import type { MailMessage } from "./mailer.ts";

type Template = Omit<MailMessage, "to">;

const linkEmail = (
	subject: string,
	intro: string,
	url: string,
	expiresAt?: Date,
): Template => {
	const expiry = expiresAt
		? ` The link expires at ${expiresAt.toISOString()}.`
		: "";
	return {
		subject,
		text: `${intro}\n\n${url}\n\n${expiry.trim()}`,
		html: `<p>${intro}</p><p><a href="${url}">${url}</a></p><p>${expiry}</p>`,
	};
};

export const templates = {
	verifyEmail: (appName: string, url: string, expiresAt: Date) =>
		linkEmail(
			`Verify your ${appName} email address`,
			"Confirm your email address:",
			url,
			expiresAt,
		),
	resetPassword: (appName: string, url: string, expiresAt: Date) =>
		linkEmail(
			`Reset your ${appName} password`,
			"Someone asked to reset your password. If it was you, choose a new one:",
			url,
			expiresAt,
		),
	magicLink: (appName: string, url: string, expiresAt: Date) =>
		linkEmail(
			`Sign in to ${appName}`,
			"Sign in with this link:",
			url,
			expiresAt,
		),
	invitation: (
		appName: string,
		inviter: string,
		organization: string,
		url: string,
	) =>
		linkEmail(
			`${inviter} invited you to ${organization} on ${appName}`,
			`${inviter} invited you to join ${organization}.`,
			url,
		),
	welcome: (appName: string, name: string): Template => ({
		subject: `Welcome to ${appName}`,
		text: `Hi ${name}, your account is ready.`,
	}),
	goodbye: (appName: string, name: string): Template => ({
		subject: `Your ${appName} account was deleted`,
		text: `Hi ${name}, your account and its data were deleted.`,
	}),
};
