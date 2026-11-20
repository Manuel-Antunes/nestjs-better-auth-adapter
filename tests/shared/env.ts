/**
 * Runs `fn` with `vars` set in `process.env`, then puts the previous values
 * back. (Not `vi.stubEnv`: Bun's test runner doesn't have it.)
 */
export async function withEnv<T>(
	vars: Record<string, string>,
	fn: () => Promise<T>,
): Promise<T> {
	const previous = Object.fromEntries(
		Object.keys(vars).map((name) => [name, process.env[name]]),
	);
	Object.assign(process.env, vars);
	try {
		return await fn();
	} finally {
		for (const [name, value] of Object.entries(previous)) {
			if (value === undefined) delete process.env[name];
			else process.env[name] = value;
		}
	}
}
