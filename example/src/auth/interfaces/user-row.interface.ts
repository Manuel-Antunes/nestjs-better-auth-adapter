/** A user row, as Better Auth hands it to the database hooks. */
export interface UserRow {
	id: string;
	email: string;
	name: string;
	role?: string | null;
	banned?: boolean | null;
	emailVerified?: boolean;
}
