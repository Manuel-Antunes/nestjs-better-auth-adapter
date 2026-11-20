import { AuthenticationRegistry } from "@nestjs/authentication";
import type { BetterAuthOptions } from "better-auth";
import { AccountLinkingResolver } from "../src/auth/handlers/account-linking.resolver.ts";
import { createTestApp, type TestApp } from "./support/test-app.ts";
import { setRole, signUpVerified, type TestUser } from "./support/users.ts";

/**
 * Social sign-in needs a real provider: these tests call Better Auth's
 * `user.validateUserInfo` gate with what Better Auth's OAuth callback passes
 * it before attaching a GitHub identity to an existing user. The library's
 * own tests run the whole OAuth flow.
 */
describe("account linking (OidcAccountResolver)", () => {
	let t: TestApp;

	beforeAll(async () => {
		t = await createTestApp();
	});
	afterAll(async () => {
		await t.app.close();
	});

	/** Better Auth's gate, for a GitHub identity it is about to attach to `user`. */
	const attachGithub = async (
		user: TestUser,
		action: "link-account" | "sign-in",
		subject = `gh-${user.id}`,
	) => {
		// The resolved options: the app's config, with BetterAuthModule's gate.
		const { options } = (await t.auth.$context) as {
			options: BetterAuthOptions;
		};
		return options.user?.validateUserInfo?.(
			{
				user: { id: user.id, email: user.email, emailVerified: true },
				source: {
					action,
					method: "oauth",
					oauth: {
						providerId: "github",
						profile: { id: subject, email: user.email },
					},
				},
			},
			{} as never,
		);
	};

	it("is registered as the oidc handler of AuthenticationRegistry", () => {
		expect(t.app.get(AuthenticationRegistry).handler("oidc")).toBe(
			t.app.get(AccountLinkingResolver),
		);
	});

	it("confirms the user Better Auth links a provider to", async () => {
		const user = await signUpVerified(t);
		await expect(attachGithub(user, "link-account")).resolves.toBeUndefined();
	});

	it("refuses providers for admins, who sign in with a password and a second factor", async () => {
		const admin = await signUpVerified(t, { name: "Alice Admin" });
		await setRole(t, admin, "admin");
		await expect(attachGithub(admin, "link-account")).resolves.toEqual({
			error: "account_link_refused",
			errorDescription: "This account can't be linked.",
		});
	});

	it("is asked at each sign-in with a linked provider: a promoted user loses it", async () => {
		const user = await signUpVerified(t);
		const ctx = await t.auth.$context;
		await ctx.internalAdapter.linkAccount({
			userId: user.id,
			providerId: "github",
			accountId: `gh-${user.id}`,
		});
		await expect(attachGithub(user, "sign-in")).resolves.toBeUndefined();

		await setRole(t, user, "admin");
		await expect(attachGithub(user, "sign-in")).resolves.toMatchObject({
			error: "account_link_refused",
		});
	});
});
