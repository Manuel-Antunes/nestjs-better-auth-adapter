import {
	AuthenticationError,
	type AuthenticationErrorOptions,
} from "@nestjs/authentication";

/**
 * An OAuth access token that didn't verify: forged, expired, for another
 * resource, missing its DPoP proof, or whose user or session is gone. A 401
 * whose challenge carries RFC 6750's error (`invalid_token` by default) and
 * RFC 9728's `resource_metadata`.
 */
export class OAuthAccessTokenError extends AuthenticationError {
	constructor(
		description: string,
		options: Omit<AuthenticationErrorOptions, "details"> = {},
	) {
		super(description, {
			...options,
			code: options.code ?? "invalid_token",
		});
		this.name = "OAuthAccessTokenError";
	}
}
