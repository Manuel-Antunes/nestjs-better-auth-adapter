import { Logger } from "@nestjs/common";
import type { BetterAuthOptions } from "better-auth";
import { BetterAuthConfigurationError } from "../errors/better-auth-configuration.error.ts";
import type {
	AppliedAugmentation,
	Augmentation,
} from "../interfaces/augmentation.interface.ts";
import type {
	BetterAuthAugmentOptions,
	BetterAuthCallback,
	BetterAuthCallbackAt,
	BetterAuthCallbackPath,
	BetterAuthConfigHost,
	BetterAuthPluginOptions,
} from "../interfaces/better-auth-config-augmenter.interface.ts";
import type { Auth } from "../interfaces/better-auth-module-options.interface.ts";
import type { BetterAuthPluginId } from "../interfaces/better-auth-plugin.interface.ts";
import { PLACEHOLDER } from "../plugin/placeholders.ts";
import { findPlugin } from "../plugins.ts";
import { BetterAuthPluginConfigAugmenter } from "./better-auth-plugin-config-augmenter.ts";

type Section = Record<string, unknown>;

/** Keys a path never goes through: they'd reach `Object.prototype`. */
const FORBIDDEN = new Set(["__proto__", "constructor", "prototype"]);

/** Top-level options that aren't config, or that `plugin()` reaches. */
const NOT_CONFIG = new Set([
	"database",
	"secondaryStorage",
	"logger",
	"plugins",
]);

const isSection = (value: unknown): value is Section =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * Plugs callbacks of your own into a Better Auth instance, typed from its
 * type: the paths are its configured sections' callbacks
 * (`"user.changeEmail.sendChangeEmailConfirmation"` once `user.changeEmail`
 * is configured), each taking the signature Better Auth declares.
 *
 * Changes are queued in the order they're made, and `apply()` makes them,
 * in Better Auth's options and in the copy of them its context holds, which
 * its endpoints read. `restore()` puts back what they replaced, last first.
 * A section the instance doesn't configure fails (`{ create: true }` creates
 * it), and so does a key that holds something else than a callback: a
 * callback doesn't turn its feature on.
 *
 * From a Nest provider, in `onModuleInit()` and `onModuleDestroy()`, with
 * the instance `BetterAuthService` holds (typed by `BetterAuthService<typeof auth>`).
 *
 * @example
 * ```ts
 * @Injectable()
 * export class AccountMails implements OnModuleInit, OnModuleDestroy {
 *   readonly #config: BetterAuthConfigAugmenter<typeof auth>;
 *
 *   constructor(betterAuth: BetterAuthService<typeof auth>, private readonly mailer: Mailer) {
 *     this.#config = new BetterAuthConfigAugmenter(betterAuth.instance)
 *       .replace("user.changeEmail.sendChangeEmailConfirmation", async ({ user, newEmail, url }) =>
 *         this.mailer.send(user.email, `Confirm the change to ${newEmail}`, url),
 *       )
 *       .replace("user.deleteUser.sendDeleteAccountVerification", async ({ user, url }) =>
 *         this.mailer.send(user.email, "Confirm the deletion of your account", url),
 *       );
 *   }
 *
 *   onModuleInit() {
 *     return this.#config.apply();
 *   }
 *
 *   onModuleDestroy() {
 *     this.#config.restore();
 *   }
 * }
 * ```
 */
export class BetterAuthConfigAugmenter<A extends BetterAuthConfigHost = Auth> {
	readonly #auth: A;
	readonly #logger = new Logger(BetterAuthConfigAugmenter.name);
	readonly #queued: Augmentation[] = [];
	readonly #applied: AppliedAugmentation[] = [];

	constructor(auth: A) {
		this.#auth = auth;
	}

	/** Replaces the callback at `path`, in a section the instance configures. */
	replace<const P extends BetterAuthCallbackPath<A["options"]>>(
		path: P,
		callback: BetterAuthCallbackAt<BetterAuthOptions, P>,
	): this;
	/** Replaces the callback at `path`, creating the sections that aren't configured. */
	replace<const P extends BetterAuthCallbackPath>(
		path: P,
		callback: BetterAuthCallbackAt<BetterAuthOptions, P>,
		options: BetterAuthAugmentOptions,
	): this;
	replace(
		path: string,
		callback: BetterAuthCallback,
		options?: BetterAuthAugmentOptions,
	): this {
		this.#queue(path, () => callback, {
			replaces: true,
			create: options?.create === true,
		});
		return this;
	}

	/**
	 * Replaces the callback at `path` with what `wrapper` builds from it
	 * (`undefined` when the config has none), to run code around it.
	 */
	wrap<const P extends BetterAuthCallbackPath<A["options"]>>(
		path: P,
		wrapper: (
			original: BetterAuthCallbackAt<BetterAuthOptions, P> | undefined,
		) => BetterAuthCallbackAt<BetterAuthOptions, P>,
	): this;
	/** Wraps the callback at `path`, creating the sections that aren't configured. */
	wrap<const P extends BetterAuthCallbackPath>(
		path: P,
		wrapper: (
			original: BetterAuthCallbackAt<BetterAuthOptions, P> | undefined,
		) => BetterAuthCallbackAt<BetterAuthOptions, P>,
		options: BetterAuthAugmentOptions,
	): this;
	wrap(
		path: string,
		wrapper: (original: BetterAuthCallback | undefined) => BetterAuthCallback,
		options?: BetterAuthAugmentOptions,
	): this {
		this.#queue(path, wrapper, {
			replaces: false,
			create: options?.create === true,
		});
		return this;
	}

	/**
	 * The callbacks of the plugin `id`, which the instance configures, typed
	 * as the plugin declares its options: `augment` changes them, in turn
	 * with this augmenter's other changes.
	 */
	plugin<const Id extends BetterAuthPluginId<A>>(
		id: Id,
		augment: (
			plugin: BetterAuthPluginConfigAugmenter<BetterAuthPluginOptions<A, Id>>,
		) => unknown,
	): this {
		augment(
			new BetterAuthPluginConfigAugmenter((path, callback, replaces) =>
				this.#queue(path, callback, { plugin: id, replaces, create: false }),
			),
		);
		return this;
	}

	/**
	 * Makes the queued changes, in order, once Better Auth built its
	 * context. Throws on the first that can't be made, which changes
	 * nothing: those before it stay applied, for `restore()`.
	 */
	async apply(): Promise<this> {
		const { options } = await this.#auth.$context;
		while (this.#queued.length) {
			const change = this.#queued.shift() as Augmentation;
			this.#applied.push(this.#apply(change, this.#roots(change, options)));
		}
		return this;
	}

	/** Puts back what the applied changes replaced, last first, and drops the queued ones. */
	restore(): void {
		this.#queued.length = 0;
		for (const applied of this.#applied.splice(0).reverse()) {
			for (const { section, key, had, previous } of applied.leaves) {
				if (had) section[key] = previous;
				else delete section[key];
			}
			for (const { section, key } of [...applied.created].reverse())
				delete section[key];
		}
	}

	/**
	 * Queues the change `path` asks for, checked: a path of sections ending
	 * with a callback, below the top level of Better Auth's options (which
	 * it copies into its context), anywhere in a plugin's.
	 */
	#queue(
		path: string,
		callback: Augmentation["callback"],
		{
			plugin,
			replaces,
			create,
		}: Pick<Augmentation, "plugin" | "replaces" | "create">,
	): void {
		const sections = typeof path === "string" ? path.split(".") : [];
		if (!sections.length || sections.some((key) => !key || FORBIDDEN.has(key)))
			throw new BetterAuthConfigurationError(
				`${JSON.stringify(path)} isn't the path of a callback in Better Auth's options.`,
			);
		if (!plugin && sections.length < 2)
			throw new BetterAuthConfigurationError(
				`'${path}' is a top-level option, which Better Auth copies when the instance is created: set it in betterAuth({...}).`,
			);
		if (!plugin && NOT_CONFIG.has(sections[0] as string))
			throw new BetterAuthConfigurationError(
				`'${path}' isn't Better Auth's config but something it calls: set it in betterAuth({...})${sections[0] === "plugins" ? ", or reach a plugin's options with plugin()" : ""}.`,
			);
		const key = sections.pop() as string;
		this.#queued.push({
			plugin,
			path,
			sections,
			key,
			callback,
			replaces,
			create,
		});
	}

	/**
	 * Where `change` goes: Better Auth's options and its context's copy of
	 * them, whose sections are mostly the same objects; a plugin's options,
	 * which the plugin keeps.
	 */
	#roots(change: Augmentation, contextOptions: object): object[] {
		if (!change.plugin)
			return [...new Set([this.#auth.options, contextOptions])];
		const options = findPlugin(
			this.#auth as BetterAuthConfigHost,
			change.plugin,
		)?.options;
		if (!isSection(options))
			throw new BetterAuthConfigurationError(
				`'${change.path}' is in the ${change.plugin} plugin's options, but ${
					options === undefined
						? findPlugin(this.#auth as BetterAuthConfigHost, change.plugin)
							? "it was created without any"
							: "the plugin isn't configured"
						: "they aren't an object"
				}.`,
			);
		return [options];
	}

	/**
	 * Makes `change` in each of `roots` (a section they share, once), or
	 * throws before changing anything: a section that isn't configured
	 * (unless `create`), or a key holding something else than a callback.
	 */
	#apply(change: Augmentation, roots: object[]): AppliedAugmentation {
		const where = change.plugin
			? `the ${change.plugin} plugin's options`
			: "Better Auth's options";
		// Every root checked first: a failed change leaves none half made.
		type Walk = { section: Section; missing: string[] };
		let unconfigured: { path: string; found: unknown } | undefined;
		const walks = roots.flatMap((root): Walk[] => {
			let section = root as Section;
			for (const [index, key] of change.sections.entries()) {
				const next = section[key];
				if (next === undefined && change.create)
					return [{ section, missing: change.sections.slice(index) }];
				if (!isSection(next)) {
					// Another root may have it: a plugin's init() adds sections to
					// the context's options only.
					unconfigured ??= {
						path: change.sections.slice(0, index + 1).join("."),
						found: next,
					};
					return [];
				}
				section = next;
			}
			const current = section[change.key];
			if (current !== undefined && typeof current !== "function")
				throw new BetterAuthConfigurationError(
					`'${change.path}' in ${where} holds a ${typeof current}, not a callback.`,
				);
			return [{ section, missing: [] }];
		});
		if (!walks.length && unconfigured)
			throw new BetterAuthConfigurationError(
				`'${change.path}' needs '${unconfigured.path}' configured in ${where}${unconfigured.found === undefined ? "" : ", as an object"}: a callback doesn't turn its feature on.`,
			);

		const applied: AppliedAugmentation = { leaves: [], created: [] };
		const changed = new Set<object>();
		for (const walk of walks) {
			let section = walk.section;
			for (const key of walk.missing) {
				const created: Section = {};
				section[key] = created;
				applied.created.push({ section, key });
				section = created;
			}
			if (changed.has(section)) continue;
			changed.add(section);

			const had = Object.hasOwn(section, change.key);
			const previous = section[change.key];
			const original =
				typeof previous === "function"
					? (previous as BetterAuthCallback)
					: undefined;
			if (
				change.replaces &&
				applied.leaves.length === 0 &&
				original &&
				!(original as { [PLACEHOLDER]?: true })[PLACEHOLDER]
			)
				this.#logger.log(
					`'${change.path}' replaces the callback the config defines.`,
				);
			section[change.key] = change.callback(original);
			applied.leaves.push({ section, key: change.key, had, previous });
		}
		return applied;
	}
}
