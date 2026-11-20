/**
 * Whether a JWT's header types it as an OAuth access token (RFC 9068
 * `at+jwt`), as the `oauthProvider()` plugin signs them. They are signed
 * with the `jwt()` plugin's keys, so only their type tells them apart from
 * the plugin's own JWTs.
 */
export function isOAuthAccessToken(token: string): boolean {
	const header = token.split(".", 1)[0];
	if (!header) return false;
	try {
		const { typ } = JSON.parse(Buffer.from(header, "base64url").toString());
		return (
			typeof typ === "string" && /^(application\/)?at\+jwt$/i.test(typ.trim())
		);
	} catch {
		return false;
	}
}
