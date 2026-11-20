/** `user.role`, set by Better Auth's `admin()` plugin: what a person may do on the platform. */
export enum PlatformRole {
	Admin = "admin",
	/** Customer support: reads the audit trail, nothing else. */
	Support = "support",
	User = "user",
}
