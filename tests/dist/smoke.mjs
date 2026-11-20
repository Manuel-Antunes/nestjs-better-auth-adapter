/**
 * Boots an app from the built package (`dist`), with no TypeScript
 * transform: the build emits no decorator metadata, so every injection must
 * be explicit (`@Inject`). The e2e suites run from source through SWC, which
 * emits metadata, and would not notice. Run after `bun run build`.
 */
import "reflect-metadata";
import assert from "node:assert/strict";
import {
	AuthenticationModule,
	AuthenticationRegistry,
	CurrentUser,
} from "@nestjs/authentication";
import { Controller, Get, Inject, Injectable, Module } from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import { betterAuth } from "better-auth";
import { admin } from "better-auth/plugins/admin";
import { bearer } from "better-auth/plugins/bearer";
import {
	BetterAuthAccessControl,
	BetterAuthModule,
	BetterAuthService,
	BetterAuthSessionProvider,
} from "../../dist/index.mjs";
import {
	BetterAuthAuthorizationModule,
	BetterAuthPermissionPolicy,
} from "../../dist/authorization/index.mjs";
import { nestPasswordHasher, nestjs } from "../../dist/plugin/index.mjs";
import * as core from "../../dist/index.mjs";
import * as oauthProvider from "../../dist/oauth-provider/index.mjs";

class MeController {
	me(user) {
		return { id: user.id };
	}
}
Controller()(MeController);
CurrentUser()(MeController.prototype, "me", 0);
Get("me")(
	MeController.prototype,
	"me",
	Object.getOwnPropertyDescriptor(MeController.prototype, "me"),
);

/** The app's session provider: its `BetterAuthService` is property-injected. */
class SessionAuth extends BetterAuthSessionProvider {
	constructor(registry) {
		super();
		registry.registerProvider(this, { order: 0 });
	}
}
Injectable()(SessionAuth);
Inject(AuthenticationRegistry)(SessionAuth, undefined, 0);

let auth;
class AppModule {}
Module({
	imports: [
		AuthenticationModule.forRoot({ password: { logN: 10 } }),
		BetterAuthModule.forRootAsync({
			inject: [BetterAuthAccessControl],
			useFactory: (accessControl) => {
				auth = betterAuth({
					emailAndPassword: { enabled: true, password: nestPasswordHasher() },
					logger: { disabled: true },
					plugins: [bearer(), admin(accessControl.admin()), nestjs()],
				});
				return { auth };
			},
		}),
		BetterAuthAuthorizationModule,
	],
	controllers: [MeController],
	providers: [SessionAuth],
})(AppModule);

const warnings = [];
const logger = {
	log() {},
	error: (message) => warnings.push(String(message)),
	warn: (message) => warnings.push(String(message)),
};
const app = await NestFactory.create(AppModule, { bodyParser: false, logger });
await app.listen(0);

try {
	assert.deepEqual(warnings, [], `unexpected warnings: ${warnings.join("\n")}`);
	assert.equal(app.get(BetterAuthService).instance, auth);
	app.get(BetterAuthPermissionPolicy);

	const { token, user } = await auth.api.signUpEmail({
		body: { name: "Smoke", email: "smoke@example.com", password: "password-123456" },
	});
	const url = `${await app.getUrl()}/me`;
	const signedIn = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
	assert.equal(signedIn.status, 200);
	assert.deepEqual(await signedIn.json(), { id: user.id });
	assert.equal((await fetch(url)).status, 401);

	// The resource server is its own entrypoint, not part of the core.
	for (const name of [
		"BetterAuthOAuthProvider",
		"BetterAuthOAuthProviderModule",
		"OAuthScopes",
		"OAuthAccessTokenError",
	]) {
		assert.equal(typeof oauthProvider[name], "function", name);
		assert.equal(name in core, false, `${name} is in the core entrypoint`);
	}

	console.log("dist smoke test passed");
} finally {
	await app.close();
}
