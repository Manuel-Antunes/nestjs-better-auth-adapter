import type { PasswordHasher } from "@nestjs/authentication";
import type {
	BIND_PASSWORD_HASHER,
	UPGRADE_HASH,
} from "../password.constants.ts";

export interface BetterAuthPasswordOptions {
	/**
	 * Keep verifying the `salt:key` hashes Better Auth writes by default, so
	 * users who signed up before the switch can still sign in. Their hash is
	 * upgraded the next time their password is verified.
	 * @default true
	 */
	legacyHashes?: boolean;
}

/** `emailAndPassword.password` for Better Auth. */
export type BetterAuthPassword = {
	hash: (password: string) => Promise<string>;
	verify: (data: { hash: string; password: string }) => Promise<boolean>;
	[UPGRADE_HASH]?: (outdated: string, upgraded: string) => Promise<void>;
	[BIND_PASSWORD_HASHER]?: (hasher: PasswordHasher) => void;
};
