/** `member.role`, set by Better Auth's `organization()` plugin: what a member may do in one organization. */
export enum OrganizationRole {
	Owner = "owner",
	Admin = "admin",
	Member = "member",
	/** Finance people: see and change the plan, no access to projects. */
	Billing = "billing",
}
