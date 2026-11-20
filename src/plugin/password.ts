import type { PasswordHasher } from "@nestjs/authentication";
import { verifyPassword as verifyBetterAuthHash } from "better-auth/crypto";
import { BetterAuthConfigurationError } from "../errors/better-auth-configuration.error.ts";
import type {
	BetterAuthPassword,
	BetterAuthPasswordOptions,
} from "./interfaces/password.interface.ts";
import { BIND_PASSWORD_HASHER, UPGRADE_HASH } from "./password.constants.ts";

/**
 * Hashes with Nest's `PasswordHasher`. A password verified against an
 * outdated hash (Better Auth's own format, or scrypt at an older cost) is
 * rehashed then, the only time the plaintext is known: wherever Better Auth
 * verifies it (any sign-in, a password change), once the `nestjs()` plugin
 * provided the store.
 */
function nestPassword(
	hasher: () => PasswordHasher,
	{ legacyHashes = true }: BetterAuthPasswordOptions,
): BetterAuthPassword {
	const password: BetterAuthPassword = {
		[UPGRADE_HASH]: undefined,
		hash: async (plaintext) => hasher().hash(plaintext),
		verify: async ({ hash, password: plaintext }) => {
			const current = hasher();
			const isScrypt = hash.startsWith("$scrypt$");
			const valid = isScrypt
				? await current.verify(plaintext, hash)
				: legacyHashes &&
					(await verifyBetterAuthHash({ hash, password: plaintext }));

			const store = password[UPGRADE_HASH];
			if (valid && store && (!isScrypt || current.needsRehash(hash))) {
				// The password is right: an upgrade that fails must not refuse it.
				await current.hash(plaintext).then(
					(upgraded) => store(hash, upgraded),
					() => undefined,
				);
			}
			return valid;
		},
	};
	return password;
}

/**
 * `emailAndPassword.password` backed by Nest's `PasswordHasher`: scrypt at
 * OWASP settings, constant-time checks, NFKC normalization and length
 * limits, with its cost set once in `AuthenticationModule.forRoot({ password })`.
 *
 * @example
 * ```ts
 * BetterAuthModule.forRootAsync({
 *   inject: [PasswordHasher],
 *   useFactory: (hasher: PasswordHasher) => ({
 *     auth: betterAuth({
 *       emailAndPassword: { enabled: true, password: betterAuthPassword(hasher) },
 *       plugins: [nestjs()],
 *     }),
 *   }),
 * })
 * ```
 */
export function betterAuthPassword(
	hasher: PasswordHasher,
	options: BetterAuthPasswordOptions = {},
): BetterAuthPassword {
	return nestPassword(() => hasher, options);
}

/**
 * {@link betterAuthPassword} for an `auth` instance built before Nest can
 * inject `PasswordHasher`, as with `BetterAuthModule.forRoot({ auth })` or
 * the file the Better Auth CLI reads. Better Auth captures `hash` and
 * `verify` when it starts, so they can't be swapped later: this placeholder
 * goes in the config, and `BetterAuthModule` binds it to the injected
 * `PasswordHasher` at startup.
 *
 * @example
 * ```ts
 * betterAuth({ emailAndPassword: { enabled: true, password: nestPasswordHasher() } })
 * ```
 */
export function nestPasswordHasher(
	options: BetterAuthPasswordOptions = {},
): BetterAuthPassword {
	let bound: PasswordHasher | undefined;
	const password = nestPassword(() => {
		if (!bound)
			throw new BetterAuthConfigurationError(
				"nestPasswordHasher() is not bound: import BetterAuthModule and AuthenticationModule so it can use Nest's PasswordHasher.",
			);
		return bound;
	}, options);
	password[BIND_PASSWORD_HASHER] = (hasher) => {
		bound = hasher;
	};
	return password;
}
