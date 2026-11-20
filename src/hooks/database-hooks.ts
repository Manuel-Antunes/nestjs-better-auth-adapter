import type {
	DatabaseHookData as Data,
	DatabaseHookFn,
	DatabaseHookModel,
	DatabaseHookOperation,
} from "../interfaces/hooks.interface.ts";
import type { NestBridge } from "../plugin/interfaces/bridge.interface.ts";

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
