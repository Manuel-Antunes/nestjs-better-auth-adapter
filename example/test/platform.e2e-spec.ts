import { createTestApp, type TestApp } from "./support/test-app.ts";
import {
	enrollAndStepUp,
	PASSWORD,
	setRole,
	signUp,
	signUpVerified,
	type TestUser,
} from "./support/users.ts";

describe("platform: articles, admins and the audit trail (admin() plugin access control)", () => {
	let t: TestApp;
	let author: TestUser;
	let reader: TestUser;
	let admin: TestUser;
	let support: TestUser;

	beforeAll(async () => {
		t = await createTestApp();
		author = await signUpVerified(t, { name: "Ada Author" });
		reader = await signUpVerified(t, { name: "Rui Reader" });
		admin = await signUpVerified(t, { name: "Alice Admin" });
		support = await signUpVerified(t, { name: "Sam Support" });
		await setRole(t, admin, "admin");
		await setRole(t, support, "support");
	});
	afterAll(async () => {
		await t.app.close();
	});

	const writeArticle = async (user: TestUser, title = "Draft") => {
		const { body } = await t
			.http()
			.post("/api/v1/articles")
			.set("Authorization", user.bearer)
			.send({ title, body: "…" })
			.expect(201);
		return body as { id: string; status: string };
	};

	describe("ArticlePolicy (BetterAuthACPolicy with a record-level rule)", () => {
		it("shows drafts to their author only (@Authenticate({ optional: true }))", async () => {
			const draft = await writeArticle(author, "Secret draft");
			await t.http().get(`/api/v1/articles/${draft.id}`).expect(404);
			await t
				.http()
				.get(`/api/v1/articles/${draft.id}`)
				.set("Authorization", reader.bearer)
				.expect(404);
			const { body } = await t
				.http()
				.get(`/api/v1/articles/${draft.id}`)
				.set("Authorization", author.bearer)
				.expect(200);
			expect(body.permissions).toEqual({ canUpdate: true, canDelete: true });
		});

		it("lets authors edit their own article, not someone else's (AuthorizationService.authorize)", async () => {
			const article = await writeArticle(author);
			await t
				.http()
				.patch(`/api/v1/articles/${article.id}`)
				.set("Authorization", author.bearer)
				.send({ title: "Edited" })
				.expect(200);

			const published = await writeArticle(author, "Public");
			await t
				.http()
				.post(`/api/v1/articles/${published.id}/publish`)
				.set("Authorization", admin.bearer)
				.expect(201);
			await t
				.http()
				.patch(`/api/v1/articles/${published.id}`)
				.set("Authorization", reader.bearer)
				.send({ title: "Vandalized" })
				.expect(403);
		});

		it("leaves publishing to admins (`manage` expands to every action)", async () => {
			const article = await writeArticle(author);
			await t
				.http()
				.post(`/api/v1/articles/${article.id}/publish`)
				.set("Authorization", author.bearer)
				.expect(403);
			const { body } = await t
				.http()
				.post(`/api/v1/articles/${article.id}/publish`)
				.set("Authorization", admin.bearer)
				.expect(201);
			expect(body.status).toBe("published");

			const anonymous = await t.http().get("/api/v1/articles").expect(200);
			expect(anonymous.body.map((a: { id: string }) => a.id)).toContain(
				article.id,
			);
		});

		it("lets admins moderate anyone's article", async () => {
			const article = await writeArticle(author);
			const { body } = await t
				.http()
				.get(`/api/v1/articles/${article.id}`)
				.set("Authorization", admin.bearer)
				.expect(404); // a draft: not visible to them…
			expect(body.message).toBe("Article not found");

			await t
				.http()
				.post(`/api/v1/articles/${article.id}/publish`)
				.set("Authorization", admin.bearer)
				.expect(201);
			await t
				.http()
				.delete(`/api/v1/articles/${article.id}`)
				.set("Authorization", admin.bearer)
				.expect(204);
		});
	});

	describe("AuditLogPolicy (custom PlatformPolicy mixin: kebab-case resource, admin manages all)", () => {
		it("lets support read the trail, not export it; admins do both", async () => {
			await t
				.http()
				.get("/api/v1/admin/audit-events")
				.set("Authorization", support.bearer)
				.expect(200);
			await t
				.http()
				.get("/api/v1/admin/audit-events/export")
				.set("Authorization", support.bearer)
				.expect(403);
			const csv = await t
				.http()
				.get("/api/v1/admin/audit-events/export")
				.set("Authorization", admin.bearer)
				.expect(200);
			expect(csv.headers["content-type"]).toContain("text/csv");
			expect(csv.text.split("\n")[0]).toBe(
				"created_at,action,actor_id,ip_address",
			);
		});

		it("denies regular users", async () => {
			await t
				.http()
				.get("/api/v1/admin/audit-events")
				.set("Authorization", reader.bearer)
				.expect(403);
		});
	});

	describe("the admin() plugin's own routes, checked against the ac the policies built", () => {
		const ban = (by: TestUser, userId: string) =>
			t
				.http()
				.post("/api/auth/admin/ban-user")
				.set("Authorization", by.bearer)
				.send({ userId, banReason: "spam" });

		it("lists users for the roles granted Better Auth's user:list statement", async () => {
			await t
				.http()
				.get("/api/auth/admin/list-users")
				.set("Authorization", reader.bearer)
				.expect(403);
			const { body } = await t
				.http()
				.get("/api/auth/admin/list-users")
				.query({ limit: 5 })
				.set("Authorization", admin.bearer)
				.expect(200);
			expect(body.users.length).toBeGreaterThan(0);
		});

		it("bans with user:ban and a second factor (SensitiveRoutesHooks): the user's sessions end", async () => {
			const target = await signUp(t);
			const refused = await ban(admin, target.id).expect(401);
			expect(refused.body.code).toBe("MFA_REQUIRED");

			// A second factor, but Better Auth's ac doesn't grant support user:ban.
			await enrollAndStepUp(t, support);
			await ban(support, target.id).expect(403);

			await enrollAndStepUp(t, admin);
			await ban(admin, target.id).expect(200);
			await t
				.http()
				.get("/api/v1/me")
				.set("Authorization", target.bearer)
				.expect(401);
			await t
				.http()
				.post("/api/auth/sign-in/email")
				.send({ email: target.email, password: PASSWORD })
				.expect(403);
		});

		it("answers Better Auth's own refusals: admins can't ban themselves", async () => {
			const response = await ban(admin, admin.id).expect(400);
			expect(response.body.code).toBe("YOU_CANNOT_BAN_YOURSELF");
		});
	});

	describe("deleting an account", () => {
		it("deletes the drafts (@BeforeDelete), keeps published articles anonymized, and says goodbye (@AfterDelete)", async () => {
			const leaving = await signUpVerified(t, { name: "Leo Leaving" });
			const draft = await writeArticle(leaving, "Unfinished");
			const published = await writeArticle(leaving, "Finished");
			await t
				.http()
				.post(`/api/v1/articles/${published.id}/publish`)
				.set("Authorization", admin.bearer)
				.expect(201);

			await t
				.http()
				.post("/api/auth/delete-user")
				.set("Authorization", leaving.bearer)
				.send({ password: PASSWORD })
				.expect(200);

			await t
				.http()
				.get(`/api/v1/articles/${draft.id}`)
				.set("Authorization", admin.bearer)
				.expect(404);
			const { body } = await t
				.http()
				.get(`/api/v1/articles/${published.id}`)
				.expect(200);
			expect(body.authorId).toBeNull();
			await vi.waitFor(() =>
				t.mailer.last(leaving.email, /account was deleted/),
			);
		});
	});
});
