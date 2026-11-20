import type {
	AuthenticationModuleOptions,
	OidcAccountResolver,
	OidcProfile,
} from "@nestjs/authentication";
import { getOAuthState } from "better-auth/api";
import { BetterAuthConfigurationError } from "../errors/better-auth-configuration.error.ts";
import type {
	ValidateUserInfoData,
	ValidateUserInfoResult,
} from "../interfaces/handlers.interface.ts";

/** The `oidc` option keys that keep a meaning with Better Auth. */
const MEANINGFUL = new Set(["callbackUrl", "providers"]);

/**
 * Checks the `oidc` option of `AuthenticationModule` against Better Auth,
 * which signs users in with its `socialProviders`: `callbackUrl` must be
 * Better Auth's callback route (the redirect URI registered with each
 * provider), `providers` a function (Nest's own OIDC client serves none),
 * and the client's other options, which nothing reads, are refused.
 */
export function checkOidcOptions(
	options: AuthenticationModuleOptions | undefined,
	basePath: string,
): void {
	const oidc = options?.oidc;
	const route = `${basePath}/callback/:provider`;
	if (!oidc)
		throw new BetterAuthConfigurationError(
			`An oidc handler is registered but the AuthenticationModule \`oidc\` option is missing: set its \`callbackUrl\` to Better Auth's callback, like 'https://api.example.com${route}'.`,
		);
	if (
		typeof oidc.callbackUrl === "string" &&
		new URL(oidc.callbackUrl).pathname !== route
	)
		throw new BetterAuthConfigurationError(
			`AuthenticationModule's \`oidc.callbackUrl\` must be Better Auth's callback route, '${route}', which receives the providers' redirects: got '${oidc.callbackUrl}'.`,
		);
	if (typeof oidc.providers !== "function")
		throw new BetterAuthConfigurationError(
			"AuthenticationModule's `oidc.providers` would run Nest's own OIDC client next to Better Auth's socialProviders, which sign users in: pass `providers: () => null`.",
		);
	for (const key of Object.keys(oidc)) {
		if (!MEANINGFUL.has(key) && oidc[key as keyof typeof oidc] !== undefined)
			throw new BetterAuthConfigurationError(
				`AuthenticationModule's \`oidc.${key}\` has no effect with Better Auth, whose socialProviders sign users in: configure them in Better Auth.`,
			);
	}
}

/**
 * Asks `resolver` about an identity Better Auth is about to attach to an
 * existing user: signing in with a linked provider, linking one by email,
 * or a signed-in user connecting one (`linkTo`). The resolver returns that
 * user to confirm Better Auth's choice, anything else refuses it. A new
 * identity creates a new user, which Better Auth's sign-up options govern
 * (`disableImplicitSignUp`, `disableSignUp`): the resolver isn't asked.
 */
export async function resolveIdentity(
	resolver: OidcAccountResolver,
	{ user, source }: ValidateUserInfoData,
): Promise<ValidateUserInfoResult> {
	const provider = source.oauth ?? source.sso;
	if (!provider || source.action === "create-user" || !user.id) return;

	const claims = provider.profile ?? {};
	const state = await getOAuthState().catch(() => null);
	const profile: OidcProfile = {
		provider: provider.providerId,
		subject: String(claims.sub ?? claims.id ?? ""),
		email: user.email,
		emailVerified: user.emailVerified === true,
		name: typeof user.name === "string" ? user.name : undefined,
		picture: typeof user.image === "string" ? user.image : undefined,
		claims,
	};
	const resolved = await resolver.resolveUser(
		profile,
		// Better Auth's gate runs before it stores the provider's tokens.
		{ accessToken: "" },
		{ linkTo: state?.link ? { id: state.link.userId } : undefined },
	);
	if (resolved?.id === user.id) return;
	return {
		error: "account_link_refused",
		errorDescription: "This account can't be linked.",
	};
}
