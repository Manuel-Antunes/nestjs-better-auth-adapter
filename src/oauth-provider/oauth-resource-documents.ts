import { Injectable } from "@nestjs/common";
import { BetterAuthConfigurationError } from "../errors/better-auth-configuration.error.ts";

/**
 * The RFC 9728 documents of the app's `BetterAuthOAuthProvider`s, by path:
 * each provider adds its own once it built it, and
 * `BetterAuthOAuthProviderModule` serves them.
 */
@Injectable()
export class OAuthResourceDocuments {
	readonly #documents = new Map<string, { owner: string; body: string }>();

	/** Fails when another provider already serves `path`: two for one resource can't both be served. */
	add(path: string, owner: string, body: string): void {
		const other = this.#documents.get(path);
		if (other)
			throw new BetterAuthConfigurationError(
				`${owner} and ${other.owner} both serve the resource metadata at ${path}: give each its own audience, or resourceMetadata: false to one.`,
			);
		this.#documents.set(path, { owner, body });
	}

	get(path: string): string | undefined {
		return this.#documents.get(path)?.body;
	}

	get size(): number {
		return this.#documents.size;
	}
}
