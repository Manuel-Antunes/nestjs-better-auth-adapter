import { InjectableProxy } from "nestjs-cls";

/**
 * Request id, IP and user agent of the current request, for logs and the
 * audit trail. A `nestjs-cls` proxy provider: inject it anywhere, singletons
 * and Better Auth's hooks included, and it reads the current request's values
 * (all `undefined` outside a request). Filled by {@link requestContextOptions}.
 */
@InjectableProxy()
export class RequestMetadata {
	requestId!: string;
	ipAddress!: string | null;
	userAgent!: string | null;
}
