import type { NestBridge } from "../plugin/bridge.ts";
import type {
	DatabaseHookModel,
	DatabaseHookOperation,
} from "./hook.decorators.ts";

// biome-ignore lint/suspicious/noExplicitAny: Better Auth's records vary by model and plugins
type Data = Record<string, any>;
// biome-ignore lint/suspicious/noExplicitAny: Better Auth decides what a database hook may return
type DatabaseHookFn = (data: Data, context: any) => any;

/**
 * Adds a database hook to the `nestjs()` plugin's `databaseHooks`, after the
 * ones already there. `before` hooks chain: `false` from any of them cancels
 * the write, and `{ data }` changes what the next one and the write get.
 */
export function addDatabaseHook(
	bridge: NestBridge,
	model: DatabaseHookModel,
	operation: DatabaseHookOperation,
	type: "before" | "after",
	hook: DatabaseHookFn,
): void {
	bridge.databaseHooks[model] ??= {};
	bridge.databaseHooks[model][operation] ??= {};
	const slot = bridge.databaseHooks[model][operation];
	const previous: DatabaseHookFn | undefined = slot[type];

	if (type === "after") {
		slot.after = async (data: Data, context: unknown) => {
			await previous?.(data, context);
			await hook(data, context);
		};
		return;
	}

	slot.before = async (data: Data, context: unknown) => {
		const earlier = previous ? await previous(data, context) : undefined;
		if (earlier === false) return false;
		const changes: Data | undefined = earlier?.data;

		const own = await hook(changes ? { ...data, ...changes } : data, context);
		if (own === false) return false;
		if (own?.data) return { ...own, data: { ...changes, ...own.data } };
		return earlier;
	};
}
