/** A session row, as Better Auth hands it to the database hooks. */
export interface SessionRow {
	id: string;
	userId: string;
	ipAddress?: string | null;
	userAgent?: string | null;
	activeOrganizationId?: string | null;
}
