import { createHmac } from "node:crypto";

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Decode(input: string): Buffer {
	let bits = "";
	for (const char of input.replace(/=+$/, "").toUpperCase()) {
		const value = BASE32.indexOf(char);
		if (value < 0) throw new Error(`Invalid base32 character: ${char}`);
		bits += value.toString(2).padStart(5, "0");
	}
	const bytes: number[] = [];
	for (let i = 0; i + 8 <= bits.length; i += 8) {
		bytes.push(Number.parseInt(bits.slice(i, i + 8), 2));
	}
	return Buffer.from(bytes);
}

/** The current code of the authenticator behind an `otpauth://` URI, as a phone app computes it (RFC 6238). */
export function totpCode(totpURI: string, at = Date.now()): string {
	const uri = new URL(totpURI);
	const secret = base32Decode(uri.searchParams.get("secret") ?? "");
	const digits = Number(uri.searchParams.get("digits") ?? 6);
	const period = Number(uri.searchParams.get("period") ?? 30);

	const counter = Buffer.alloc(8);
	counter.writeBigUInt64BE(BigInt(Math.floor(at / 1000 / period)));
	const hmac = createHmac("sha1", secret).update(counter).digest();
	const offset = hmac[hmac.length - 1] & 0xf;
	const value = (hmac.readUInt32BE(offset) & 0x7fffffff) % 10 ** digits;
	return value.toString().padStart(digits, "0");
}
