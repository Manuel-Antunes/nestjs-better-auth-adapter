import { createHmac } from "node:crypto";
import { createTestApp, type TestApp } from "./support/test-app.ts";
import {
	createOrganization,
	enrollAndStepUp,
	joinOrganization,
	signUp,
	signUpVerified,
	type TestUser,
} from "./support/users.ts";

describe("organizations: projects, billing and Better Auth's organization access control", () => {
	let t: TestApp;
	let owner: TestUser;
	let member: TestUser;
	let finance: TestUser;
	let outsider: TestUser;
	let organizationId: string;

	beforeAll(async () => {
		t = await createTestApp();
		owner = await signUpVerified(t, { name: "Olivia Owner" });
		member = await signUpVerified(t, { name: "Max Member" });
		finance = await signUpVerified(t, { name: "Fiona Finance" });
		outsider = await signUpVerified(t, { name: "Oscar Outsider" });

		({ id: organizationId } = await createOrganization(t, owner, "Initech"));
		await joinOrganization(t, owner, member, organizationId, "member");
		await joinOrganization(t, owner, finance, organizationId, "billing");
	});
	afterAll(async () => {
		await t.app.close();
	});

	const createProject = (user: TestUser, name = "Website") =>
		t
			.http()
			.post("/api/v1/projects")
			.set("Authorization", user.bearer)
			.send({ name });

	describe("invitations", () => {
		it("are mailed by the @AfterHook on /organization/invite-member, with the injected Mailer", () => {
			const mail = t.mailer.last(member.email, /invited you to Initech/);
			expect(mail.text).toContain("Olivia Owner invited you to join Initech");
			expect(mail.text).toContain("http://localhost:5173/invitations/");
		});

		it("need invitation:create, which Better Auth checks against the ac the policies built", async () => {
			await t
				.http()
				.post("/api/auth/organization/invite-member")
				.set("Authorization", member.bearer)
				.send({ email: "someone@example.com", role: "member", organizationId })
				.expect(403);
		});

		it("need a verified email (SensitiveRoutesHooks)", async () => {
			const unverified = await signUp(t);
			await createOrganization(t, unverified, "Unverified");
			const refused = await t
				.http()
				.post("/api/auth/organization/invite-member")
				.set("Authorization", unverified.bearer)
				.send({ email: "someone@example.com", role: "member" })
				.expect(403);
			expect(refused.body.code).toBe("EMAIL_UNVERIFIED");
		});
	});

	describe("ProjectPolicy (BetterAuthOrganizationACPolicy + activeOrganization)", () => {
		it("lets owners and members create and read projects", async () => {
			await createProject(owner, "Owner's").expect(201);
			await createProject(member, "Member's").expect(201);
			const { body } = await t
				.http()
				.get("/api/v1/projects")
				.set("Authorization", member.bearer)
				.expect(200);
			expect(body.map((p: { name: string }) => p.name)).toEqual(
				expect.arrayContaining(["Owner's", "Member's"]),
			);
		});

		it("denies what the role doesn't grant: members don't update, billing people don't see projects", async () => {
			const { body: project } = await createProject(owner, "Locked").expect(
				201,
			);
			await t
				.http()
				.patch(`/api/v1/projects/${project.id}`)
				.set("Authorization", member.bearer)
				.send({ name: "Renamed" })
				.expect(403);
			await t
				.http()
				.get("/api/v1/projects")
				.set("Authorization", finance.bearer)
				.expect(403);
		});

		it("denies a user without an active organization, and guests with 401", async () => {
			await createProject(outsider).expect(403);
			await t.http().get("/api/v1/projects").expect(401);
		});

		it("checks the organization named in the URL (a route parameter resolver)", async () => {
			await t
				.http()
				.get(`/api/v1/organizations/${organizationId}/projects`)
				.set("Authorization", member.bearer)
				.expect(200);
			await t
				.http()
				.get(`/api/v1/organizations/${organizationId}/projects`)
				.set("Authorization", outsider.bearer)
				.expect(403);
		});

		it("deleting needs the role (manage, via the wildcard) and a second factor", async () => {
			const { body: project } = await createProject(owner, "Doomed").expect(
				201,
			);
			const refused = await t
				.http()
				.delete(`/api/v1/projects/${project.id}`)
				.set("Authorization", owner.bearer)
				.expect(401);
			expect(refused.body.error).toBe("mfa_required");

			await enrollAndStepUp(t, owner);
			await t
				.http()
				.delete(`/api/v1/projects/${project.id}`)
				.set("Authorization", owner.bearer)
				.expect(204);
		});

		it("honors roles created at runtime (organization({ dynamicAccessControl }))", async () => {
			const contractor = await signUpVerified(t);
			await joinOrganization(t, owner, contractor, organizationId, "member");
			await t
				.http()
				.post("/api/auth/organization/create-role")
				.set("Authorization", owner.bearer)
				.send({
					organizationId,
					role: "auditor",
					permission: { project: ["read"] },
				})
				.expect(200);

			const { body: full } = await t
				.http()
				.get("/api/auth/organization/get-full-organization")
				.query({ organizationId })
				.set("Authorization", owner.bearer)
				.expect(200);
			const membership = full.members.find(
				(m: { userId: string }) => m.userId === contractor.id,
			);
			await t
				.http()
				.post("/api/auth/organization/update-member-role")
				.set("Authorization", owner.bearer)
				.send({ organizationId, memberId: membership.id, role: "auditor" })
				.expect(200);

			await t
				.http()
				.get("/api/v1/projects")
				.set("Authorization", contractor.bearer)
				.expect(200);
			await createProject(contractor).expect(403);
		});
	});

	describe("OrganizationAuditLogPolicy (BetterAuthOrganizationACPolicy on the organization's audit trail)", () => {
		const trail = (user: TestUser) =>
			t
				.http()
				.get("/api/v1/organizations/current/audit-events")
				.set("Authorization", user.bearer);

		it("lets owners read the organization's trail, not members, billing people or outsiders", async () => {
			const { body } = await vi.waitFor(async () => {
				const response = await trail(owner).expect(200);
				expect(
					response.body.map((event: { action: string }) => event.action),
				).toContain("project.created");
				return response;
			});
			expect(
				body.every(
					(event: { organizationId: string }) =>
						event.organizationId === organizationId,
				),
			).toBe(true);

			await trail(member).expect(403);
			await trail(finance).expect(403);
			await trail(outsider).expect(403);
		});
	});

	describe("BillingPolicy, and the payment provider's webhook", () => {
		const sign = (body: string) =>
			createHmac("sha256", "test-billing-webhook-secret")
				.update(body)
				.digest("hex");

		const webhook = (payload: object, signature?: string) => {
			const body = JSON.stringify(payload);
			return t
				.http()
				.post("/api/v1/billing/webhooks")
				.set("content-type", "application/json")
				.set("x-acme-signature", signature ?? sign(body))
				.send(body);
		};

		it("lets the owner and the custom billing role read the plan, not members", async () => {
			await t
				.http()
				.get("/api/v1/billing")
				.set("Authorization", owner.bearer)
				.expect(200);
			const { body } = await t
				.http()
				.get("/api/v1/billing")
				.set("Authorization", finance.bearer)
				.expect(200);
			expect(body).toMatchObject({
				organizationId,
				plan: "free",
				status: "active",
			});
			await t
				.http()
				.get("/api/v1/billing")
				.set("Authorization", member.bearer)
				.expect(403);
		});

		it("changing the plan needs the role and a second factor", async () => {
			await t
				.http()
				.put("/api/v1/billing/plan")
				.set("Authorization", finance.bearer)
				.send({ plan: "pro" })
				.expect(401);
			await enrollAndStepUp(t, finance);
			const { body } = await t
				.http()
				.put("/api/v1/billing/plan")
				.set("Authorization", finance.bearer)
				.send({ plan: "pro" })
				.expect(200);
			expect(body.plan).toBe("pro");
		});

		it("refuses webhooks without a valid signature over the raw body (bodyParser.rawBody)", async () => {
			await webhook(
				{ organizationId, status: "past_due" },
				"00".repeat(32),
			).expect(401);
		});

		it("freezes writes of an organization past due (ProjectPolicy.before, with an injected service)", async () => {
			await webhook({ organizationId, status: "past_due" }).expect(204);
			await createProject(owner).expect(403);
			await t
				.http()
				.get("/api/v1/projects")
				.set("Authorization", owner.bearer)
				.expect(200);

			await webhook({ organizationId, status: "active" }).expect(204);
			await createProject(owner).expect(201);
		});
	});

	describe("deleting the organization", () => {
		it("is for owners (organization:delete), after a second factor, and owners can't delete their account meanwhile (@BeforeDelete)", async () => {
			const remove = (user: TestUser) =>
				t
					.http()
					.post("/api/auth/organization/delete")
					.set("Authorization", user.bearer)
					.send({ organizationId });

			// SensitiveRoutesHooks runs before Better Auth's own check: 401 whatever the role.
			const refused = await remove(member).expect(401);
			expect(refused.body.code).toBe("MFA_REQUIRED");
			await enrollAndStepUp(t, member);
			await remove(member).expect(403);

			const kept = await t
				.http()
				.post("/api/auth/delete-user")
				.set("Authorization", owner.bearer)
				.send({ password: "correct-horse-battery-staple" })
				.expect(400);
			expect(kept.body.code).toBe("OWNS_ORGANIZATIONS");

			// The owner passed a second factor deleting a project.
			await remove(owner).expect(200);
			await t
				.http()
				.get("/api/v1/projects")
				.set("Authorization", member.bearer)
				.expect(403);
		});
	});
});
