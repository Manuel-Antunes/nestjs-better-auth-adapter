/** An account row, as Better Auth hands it to the database hooks. */
export interface AccountRow {
	userId: string;
	providerId: string;
}
