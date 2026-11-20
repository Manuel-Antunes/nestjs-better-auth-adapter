import { createTestApp, type TestApp } from "./support/test-app.ts";
import {
	adoptRotatedSession,
	enrollAndStepUp,
	PASSWORD,
	signUp,
	signUpVerified,
	stepUp,
} from "./support/users.ts";

describe("account: MFA step-up, API keys and JWTs", () => {
	let t: TestApp;

	beforeAll(async () => {
		t = await createTestApp();
	});
	afterAll(async () => {
		await t.app.close();
	});

	/** Better Auth's own route, which SensitiveRoutesHooks holds to a second factor. */
	const revokeOtherSessions = (user: { bearer: string }) =>
		t
			.http()
			.post("/api/auth/revoke-other-sessions")
			.set("Authorization", user.bearer);

	describe("a second factor (the nestjs() plugin's mfaVerifiedAt)", () => {
		it("is asked by Better Auth's sensitive routes until the session passes one", async () => {
			const user = await signUpVerified(t);
			const refused = await revokeOtherSessions(user).expect(401);
			expect(refused.body.code).toBe("MFA_REQUIRED");

			await enrollAndStepUp(t, user);
			await revokeOtherSessions(user).expect(200);
			const me = await t
				.http()
				.get("/api/v1/me")
				.set("Authorization", user.bearer);
			expect(me.body.session.mfaVerified).toBe(true);
		});

		it("doesn't count enrolling an authenticator as a second factor", async () => {
			const user = await signUpVerified(t);
			const enabled = await t
				.http()
				.post("/api/auth/two-factor/enable")
				.set("Authorization", user.bearer)
				.send({ password: PASSWORD })
				.expect(200);
			const { totpCode } = await import("./support/totp.ts");
			const confirmed = await t
				.http()
				.post("/api/auth/two-factor/verify-totp")
				.set("Authorization", user.bearer)
				.send({ code: totpCode(enabled.body.totpURI) })
				.expect(200);
			adoptRotatedSession(user, confirmed);

			// Enrolled, not verified: the session steps up with one more verification.
			await revokeOtherSessions(user).expect(401);
			await stepUp(t, user, enabled.body.backupCodes[1]);
			await revokeOtherSessions(user).expect(200);
		});

		it("verifies the session of a password sign-in challenged by twoFactor()", async () => {
			const user = await signUpVerified(t);
			const { backupCodes } = await enrollAndStepUp(t, user);

			const challenge = await t
				.http()
				.post("/api/auth/sign-in/email")
				.send({ email: user.email, password: PASSWORD })
				.expect(200);
			expect(challenge.body.twoFactorRedirect).toBe(true);
			const cookie = (challenge.headers["set-cookie"] as unknown as string[])
				.map((c) => c.split(";")[0])
				.join("; ");

			const verified = await t
				.http()
				.post("/api/auth/two-factor/verify-backup-code")
				.set("Cookie", cookie)
				.send({ code: backupCodes[2] })
				.expect(200);
			const token = verified.headers["set-auth-token"] as string;
			const me = await t
				.http()
				.get("/api/v1/me")
				.set("Authorization", `Bearer ${token}`);
			expect(me.body.session.mfaVerified).toBe(true);
		});
	});

	describe("API keys (BetterAuthApiKeyProvider)", () => {
		/** Better Auth's own route, which SensitiveRoutesHooks holds to a verified email and a second factor. */
		const createKey = (user: { bearer: string }) =>
			t
				.http()
				.post("/api/auth/api-key/create")
				.set("Authorization", user.bearer)
				.send({ name: "ci", expiresIn: 30 * 24 * 60 * 60 });

		async function userWithKey() {
			const user = await signUpVerified(t);
			await enrollAndStepUp(t, user);
			const created = await createKey(user).expect(200);
			expect(created.body.key).toMatch(/^acme_/);
			return { user, key: created.body.key as string };
		}

		it("creating one needs a verified email and a second factor", async () => {
			const unverified = await createKey(await signUp(t)).expect(403);
			expect(unverified.body.code).toBe("EMAIL_UNVERIFIED");
			const noSecondFactor = await createKey(await signUpVerified(t)).expect(
				401,
			);
			expect(noSecondFactor.body.code).toBe("MFA_REQUIRED");
		});

		it("authenticates its owner on routes restricted to ApiKeyProvider", async () => {
			const { user, key } = await userWithKey();
			const { body } = await t
				.http()
				.get("/api/v1/integrations/whoami")
				.set("x-api-key", key)
				.expect(200);
			expect(body.userId).toBe(user.id);
			expect(body.key).toMatchObject({ method: "api-key" });
		});

		it("refuses a session there, and a bad key with a generic error", async () => {
			const { user } = await userWithKey();
			await t
				.http()
				.get("/api/v1/integrations/whoami")
				.set("Authorization", user.bearer)
				.expect(401);
			const refused = await t
				.http()
				.get("/api/v1/integrations/whoami")
				.set("x-api-key", "acme_not-a-key")
				.expect(401);
			expect(refused.body.message).toBe("Invalid API key");
			expect(refused.headers["www-authenticate"]).toContain('realm="acme-api"');
		});

		it("doesn't reach the app's session-only routes", async () => {
			const { key } = await userWithKey();
			await t.http().get("/api/v1/me").set("x-api-key", key).expect(401);
		});
	});

	describe("JWTs (BetterAuthJwtProvider)", () => {
		async function jwtOf(bearer: string) {
			const { body } = await t
				.http()
				.get("/api/auth/token")
				.set("Authorization", bearer)
				.expect(200);
			return body.token as string;
		}

		it("authenticates a jwt() token, checked against the JWKS; @CurrentSession() is its claims", async () => {
			const user = await signUp(t);
			const jwt = await jwtOf(user.bearer);
			const { body } = await t
				.http()
				.get("/api/v1/internal/whoami")
				.set("Authorization", `Bearer ${jwt}`)
				.expect(200);
			expect(body.userId).toBe(user.id);
			expect(body.claims).toMatchObject({
				sub: user.id,
				email: user.email,
				role: "user",
			});
		});

		it("is refused where only sessions may act (providers: [BetterAuthSessionProvider])", async () => {
			const user = await signUp(t);
			const jwt = await jwtOf(user.bearer);
			await t
				.http()
				.get("/api/v1/me")
				.set("Authorization", `Bearer ${jwt}`)
				.expect(401);
		});

		it("answers 401 invalid_token for a tampered JWT", async () => {
			const user = await signUp(t);
			const jwt = await jwtOf(user.bearer);
			const response = await t
				.http()
				.get("/api/v1/internal/whoami")
				.set("Authorization", `Bearer ${jwt.slice(0, -4)}AAAA`)
				.expect(401);
			expect(response.headers["www-authenticate"]).toContain("invalid_token");
		});
	});
});
