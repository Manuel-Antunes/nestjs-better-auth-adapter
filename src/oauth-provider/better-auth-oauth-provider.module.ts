import {
	Global,
	Inject,
	type MiddlewareConsumer,
	Module,
	type NestModule,
} from "@nestjs/common";
import { DiscoveryModule, HttpAdapterHost } from "@nestjs/core";
import {
	getNodeRequest,
	getNodeResponse,
	getRequestPath,
} from "../http/middlewares.ts";
import { OAuthResourceDocuments } from "./oauth-resource-documents.ts";
import { OAuthScopesCheck } from "./oauth-scopes.check.ts";

/**
 * This API as a resource server of Better Auth's `oauthProvider()`: import
 * it once, next to `BetterAuthModule`, and extend `BetterAuthOAuthProvider`.
 * Global, like `BetterAuthModule`, so the providers find it in any module.
 *
 * It serves each provider's RFC 9728 metadata, the document the
 * `WWW-Authenticate` challenges of its 401s point clients to, to any
 * origin. Better Auth's own discovery documents (an authorization server's)
 * stay `BetterAuthModule`'s, as all of Better Auth's routes.
 *
 * At startup, it fails on an `@OAuthScopes()` naming a scope that
 * `oauthProvider()` doesn't issue.
 *
 * @example
 * ```ts
 * @Module({
 *   imports: [
 *     AuthenticationModule.forRoot(),
 *     BetterAuthModule.forRoot({ auth }),
 *     BetterAuthOAuthProviderModule,
 *   ],
 *   providers: [OAuthAuth],
 * })
 * export class AppModule {}
 * ```
 */
@Global()
@Module({
	imports: [DiscoveryModule],
	providers: [OAuthResourceDocuments, OAuthScopesCheck],
	exports: [OAuthResourceDocuments],
})
export class BetterAuthOAuthProviderModule implements NestModule {
	constructor(
		@Inject(HttpAdapterHost) private readonly adapterHost: HttpAdapterHost,
		@Inject(OAuthResourceDocuments)
		private readonly documents: OAuthResourceDocuments,
	) {}

	/**
	 * On the HTTP adapter, as Better Auth's handler: the documents are
	 * outside the global prefix. The providers add them later, at
	 * `onModuleInit()`, before the app listens.
	 */
	configure(_consumer: MiddlewareConsumer): void {
		const documents = this.documents;
		this.adapterHost.httpAdapter.use(
			(
				// biome-ignore lint/suspicious/noExplicitAny: the request type depends on the HTTP adapter
				req: any,
				// biome-ignore lint/suspicious/noExplicitAny: the response type depends on the HTTP adapter
				res: any,
				next: () => void,
			) => {
				if (documents.size === 0) return next();
				const body = documents.get(getRequestPath(req).split("?", 1)[0] ?? "");
				if (body === undefined) return next();
				const method = getNodeRequest(req).method;
				const response = getNodeResponse(res);
				// Public metadata: any origin may read it.
				response.setHeader("Access-Control-Allow-Origin", "*");
				if (method === "OPTIONS") {
					response.setHeader("Access-Control-Allow-Methods", "GET, HEAD");
					response.setHeader("Access-Control-Allow-Headers", "*");
					response.statusCode = 204;
					return response.end();
				}
				if (method !== "GET" && method !== "HEAD") {
					response.setHeader("Allow", "GET, HEAD, OPTIONS");
					response.statusCode = 405;
					return response.end();
				}
				response.setHeader("Content-Type", "application/json");
				response.setHeader("Cache-Control", "public, max-age=300");
				response.statusCode = 200;
				response.end(method === "HEAD" ? undefined : body);
			},
		);
	}
}
