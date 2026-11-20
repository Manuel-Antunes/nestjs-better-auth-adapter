import { BetterAuthConfigurationError } from "../errors/better-auth-configuration.error.ts";

/**
 * `@thallesp/nestjs-better-auth`'s module options that have another name,
 * or another owner, here, with what replaces each.
 */
const REPLACEMENTS = {
	disableControllers: "routes: false",
	disableGlobalAuthGuard:
		"AuthenticationModule.forRoot({ globalGuard: false }), as the global guard is @nestjs/authentication's",
	disableTrustedOriginsCors: "trustedOriginsCors: false",
	disableBodyParser:
		"bodyParser: { json: { enabled: false }, urlencoded: { enabled: false } }",
	enableRawBodyParser: "bodyParser: { rawBody: true }",
} as const;

/**
 * Fails at startup on an option of `@thallesp/nestjs-better-auth`, naming
 * what replaces it, rather than ignoring it: a guard thought off, or routes
 * thought unserved, would otherwise stay on without a word.
 */
export function assertNoThallespOptions(options: object): void {
	const found = Object.keys(REPLACEMENTS).filter(
		(option) => (options as Record<string, unknown>)[option] !== undefined,
	) as (keyof typeof REPLACEMENTS)[];
	if (!found.length) return;
	throw new BetterAuthConfigurationError(
		`BetterAuthModule doesn't take @thallesp/nestjs-better-auth's ${found.join(", ")}: ${found
			.map((option) => `for ${option}, use ${REPLACEMENTS[option]}`)
			.join("; ")}.`,
	);
}
