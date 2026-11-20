/** Base-2 byte multipliers for string body size limits (e.g. `"2mb"`). */
export const BYTE_UNITS = {
	b: 1,
	kb: 1 << 10,
	mb: 1 << 20,
	gb: 1 << 30,
} as const;
