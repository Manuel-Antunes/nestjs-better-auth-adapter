/** A configured Better Auth plugin, as this package reads it. */
export type PluginLike = { id: string; options?: Record<string, unknown> };

/**
 * A key the `apiKey()` plugin verified, as `verifyApiKey` returns it (no
 * hash): what `BetterAuthApiKeyProvider.validate()` receives. Its fields
 * vary by plugin version and configuration.
 */
export interface BetterAuthApiKey {
	id: string;
	/** The user, or the organization, the key belongs to. */
	referenceId?: string | null;
	/** Older plugin versions' `referenceId`. */
	userId?: string | null;
	configId?: string | null;
	name?: string | null;
	expiresAt?: Date | string | null;
	permissions?: Record<string, string[]> | null;
	metadata?: Record<string, unknown> | null;
	[field: string]: unknown;
}
