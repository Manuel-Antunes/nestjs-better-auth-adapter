import {
	createHash,
	generateKeyPairSync,
	randomBytes,
	randomUUID,
	sign,
} from "node:crypto";
import request from "supertest";
import { uniqueEmail } from "./app.ts";

/** Where the test clients are redirected after authorizing. */
export const REDIRECT = "https://client.test/callback";

export type OAuthClient = { client_id: string; client_secret: string };

/** `oauthProvider()`'s API, which createTestAuth()'s type doesn't carry. */
export type OAuthApi = {
	adminCreateOAuthClient(input: {
		headers: Headers;
		body: Record<string, unknown>;
	}): Promise<unknown>;
};

export type DpopKey = ReturnType<typeof dpopKey>;

/**
 * The flows a test drives against an app serving `oauthProvider()`: a user
 * signing in, an admin creating a client, and the authorization code flow.
 * `server` and `auth` are read when called, so they can be set in a
 * `beforeAll()`.
 */
export function oauthFlows(target: {
	server: () => unknown;
	auth: () => { api: unknown };
	/** The plugin's issuer, which DPoP proofs for the token endpoint sign. */
	issuer: string;
}) {
	const http = () => request(target.server() as never);

	/** A signed-in user: their session cookie. */
	const signIn = async () => {
		const response = await http()
			.post("/api/auth/sign-up/email")
			.send({ email: uniqueEmail(), password: "password1234", name: "User" });
		const cookie = (response.headers["set-cookie"] as unknown as string[])
			.map((value) => value.split(";")[0])
			.join("; ");
		return { cookie, userId: response.body.user.id as string };
	};

	const createClient = async (
		cookie: string,
		body: Record<string, unknown> = {},
	): Promise<OAuthClient> =>
		(await (target.auth().api as OAuthApi).adminCreateOAuthClient({
			headers: new Headers({ cookie }),
			body: {
				redirect_uris: [REDIRECT],
				skip_consent: true,
				scope: "openid profile read:post",
				...body,
			},
		})) as OAuthClient;

	/** The authorization code flow, PKCE and all, without consent. */
	const authorize = async (
		user: { cookie: string },
		client: OAuthClient,
		{
			scope,
			resource,
			dpop,
		}: { scope: string; resource?: string; dpop?: DpopKey },
	) => {
		const verifier = randomBytes(32).toString("base64url");
		const query = new URLSearchParams({
			response_type: "code",
			client_id: client.client_id,
			redirect_uri: REDIRECT,
			scope,
			state: "state",
			code_challenge: createHash("sha256").update(verifier).digest("base64url"),
			code_challenge_method: "S256",
			...(resource && { resource }),
		});
		const redirect = await http()
			.get(`/api/auth/oauth2/authorize?${query}`)
			.set("Cookie", user.cookie);
		const code = new URL(redirect.headers.location as string).searchParams.get(
			"code",
		);
		expect(code).toBeTruthy();

		const token = http()
			.post("/api/auth/oauth2/token")
			.type("form")
			.auth(client.client_id, client.client_secret);
		if (dpop)
			token.set("DPoP", dpop.proof("POST", `${target.issuer}/oauth2/token`));
		const response = await token.send({
			grant_type: "authorization_code",
			code,
			redirect_uri: REDIRECT,
			code_verifier: verifier,
			...(resource && { resource }),
		});
		expect(response.status).toBe(200);
		return response.body as {
			access_token: string;
			id_token?: string;
			token_type: string;
		};
	};

	return { signIn, createClient, authorize };
}

/** A client's DPoP key, signing proofs (RFC 9449) with ES256. */
export function dpopKey() {
	const { privateKey, publicKey } = generateKeyPairSync("ec", {
		namedCurve: "P-256",
	});
	const { kty, crv, x, y } = publicKey.export({ format: "jwk" });
	const encode = (value: object) =>
		Buffer.from(JSON.stringify(value)).toString("base64url");
	return {
		proof(method: string, url: string, accessToken?: string) {
			const input = `${encode({ typ: "dpop+jwt", alg: "ES256", jwk: { kty, crv, x, y } })}.${encode(
				{
					jti: randomUUID(),
					htm: method,
					htu: url,
					iat: Math.floor(Date.now() / 1000),
					...(accessToken && {
						ath: createHash("sha256").update(accessToken).digest("base64url"),
					}),
				},
			)}`;
			const signature = sign("sha256", Buffer.from(input), {
				key: privateKey,
				dsaEncoding: "ieee-p1363",
			});
			return `${input}.${signature.toString("base64url")}`;
		},
	};
}
