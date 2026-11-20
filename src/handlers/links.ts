import type { AuthenticationModuleOptions } from "@nestjs/authentication";
import { BetterAuthConfigurationError } from "../errors/better-auth-configuration.error.ts";
import type { LinkFeature } from "../interfaces/handlers.interface.ts";

/**
 * The link a handler sends: the app's page, the `url` of the feature's
 * `AuthenticationModule` option, with Better Auth's token in `?token=`, and
 * the query Better Auth put on its own link (`callbackURL`…). The page hands
 * the token to Better Auth's endpoint, as Nest's own flows have it POST back.
 */
export function pageLink(
	page: string,
	token: string,
	betterAuthUrl: string,
): string {
	const link = new URL(page);
	// Relative without a baseURL in Better Auth's config: only its query is read.
	const query = new URL(betterAuthUrl, "http://better-auth.local").searchParams;
	for (const [key, value] of query) {
		if (key !== "token") link.searchParams.set(key, value);
	}
	link.searchParams.set("token", token);
	return link.toString();
}

/** Where to set what Nest's options would set: Better Auth creates and checks the tokens. */
const OWNED_BY_BETTER_AUTH: Record<LinkFeature, Record<string, string>> = {
	passwordReset: { ttl: "emailAndPassword.resetPasswordTokenExpiresIn" },
	emailVerification: { ttl: "emailVerification.expiresIn" },
	magicLink: {
		ttl: "magicLink({ expiresIn })",
		bindToBrowser:
			"nowhere: Better Auth's magic links aren't bound to a browser",
		cookie: "nowhere: Better Auth's magic links aren't bound to a browser",
	},
};

/**
 * The feature's `AuthenticationModule` option, for a handler that delivers
 * Better Auth's links: its `url` is used, the options for the tokens
 * themselves (`ttl`…) are refused, as Better Auth's config decides those.
 */
export function featureOptions(
	options: AuthenticationModuleOptions | undefined,
	feature: LinkFeature,
): { url: string } {
	const option = options?.[feature] as Record<string, unknown> | undefined;
	if (!option)
		throw new BetterAuthConfigurationError(
			`A ${feature} handler is registered but the AuthenticationModule \`${feature}\` option is missing: set its \`url\`, the page that receives \`?token=\`.`,
		);
	for (const [key, where] of Object.entries(OWNED_BY_BETTER_AUTH[feature])) {
		if (option[key] !== undefined)
			throw new BetterAuthConfigurationError(
				`AuthenticationModule's \`${feature}.${key}\` has no effect with Better Auth, which creates and checks the tokens: set it in ${where}.`,
			);
	}
	return option as { url: string };
}
