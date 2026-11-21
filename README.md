# nestjs-better-auth-adapter

[Better Auth](https://better-auth.com) for [NestJS](https://nestjs.com), through Nest's own security packages: [`@nestjs/authentication`](https://docs.nestjs.com/security/authentication) and [`@nestjs/authorization`](https://docs.nestjs.com/security/authorization).

Better Auth stays the engine: it serves its routes (`/api/auth/*`), stores users and sessions, and runs its plugins and client SDK as usual. This package plugs it into the ports Nest defines:

| Nest port | Better Auth behind it |
| --- | --- |
| `AuthenticationRegistry` credential providers | The session (cookie, and Bearer with `bearer()`), JWTs from `jwt()`, keys from `apiKey()`, access tokens from `oauthProvider()` (from `nestjs-better-auth-adapter/oauth-provider`) |
| `@CurrentUser()`, `@CurrentSession()`, `AuthenticationContext`, `@Authenticate({ verifiedEmail, mfa, optional, providers })` | Better Auth's user and session, plugin and additional fields included |
| `PasswordResetHandler`, `EmailVerificationHandler`, `MagicLinkHandler` (through `BetterAuthPasswordResetHandler` and the others, registered in `AuthenticationRegistry`) | Deliver Better Auth's links |
| `OidcAccountResolver` (through `BetterAuthOidcAccountResolver`, registered as `oidc`) | Confirms or refuses the user Better Auth attaches a social/OAuth identity to, through `user.validateUserInfo` |
| `PasswordHasher` | Hashes Better Auth's passwords |
| `AuthenticationEvents` | Better Auth's sign-ins, sign-outs, second-factor changes, password resets and email verifications |
| `@Policy()` / `@Can()` | Better Auth's access control (`admin()` and `organization()` plugins) |

Every integration past authentication is optional: without the matching Nest provider, Better Auth keeps what its own config says.

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Authentication](#authentication)
- [Second factor (MFA)](#second-factor-mfa)
- [Authentication events](#authentication-events)
- [OAuth 2.1 and OpenID Connect provider](#oauth-21-and-openid-connect-provider)
- [Module configuration](#module-configuration)
- [Scaling: secondary storage and the cookie cache](#scaling-secondary-storage-and-the-cookie-cache)
- [Hooks](#hooks)
- [Nest handlers and `PasswordHasher`](#nest-handlers-and-passwordhasher)
- [Authorization](#authorization)
- [GraphQL and WebSockets](#graphql-and-websockets)
- [Options](#options)
- [Example app](#example-app)
- [Coming from `@thallesp/nestjs-better-auth`](#coming-from-thallespnestjs-better-auth)
- [Credits](#credits)

## Install

```bash
npm install nestjs-better-auth-adapter better-auth @nestjs/authentication
# for policies:
npm install @nestjs/authorization
```

Requires NestJS 12, `@nestjs/authentication` 0.1.6+ and Better Auth 1.7+.

## Quick start

**1. Add the `nestjs()` plugin to Better Auth.** It connects Better Auth to the Nest module: hooks, the second factor, password rehashing. It imports nothing from Nest, so the Better Auth CLI can still load the file.

```ts
// auth.ts
import { betterAuth } from "better-auth";
import { nestjs } from "nestjs-better-auth-adapter/plugin";

export const auth = betterAuth({
  database: /* your adapter */,
  emailAndPassword: { enabled: true },
  plugins: [nestjs()],
});
```

Run Better Auth's CLI afterwards (`npx auth migrate`, or `npx auth generate` for your ORM's schema): the plugin adds one column, `session.mfaVerifiedAt`.

**2. Import the modules.**

```ts
// app.module.ts
import { Module } from "@nestjs/common";
import { AuthenticationModule } from "@nestjs/authentication";
import { BetterAuthModule } from "nestjs-better-auth-adapter";
import { auth } from "./auth";

@Module({
  imports: [
    AuthenticationModule.forRoot(),
    BetterAuthModule.forRoot({ auth }),
  ],
})
export class AppModule {}
```

**3. Register the credential providers.** `BetterAuthModule` registers none itself: as with Nest's `SessionCookieProvider`, `JwtBearerProvider` and `ApiKeyProvider`, extend the base classes and register them in `AuthenticationRegistry`, where you choose their order. `BetterAuthService` is property-injected, so the constructor only lists your own dependencies.

```ts
// session.auth.ts
import { Injectable } from "@nestjs/common";
import { AuthenticationRegistry } from "@nestjs/authentication";
import { BetterAuthSessionProvider } from "nestjs-better-auth-adapter";

@Injectable()
export class SessionAuth extends BetterAuthSessionProvider {
  constructor(registry: AuthenticationRegistry) {
    super();
    registry.registerProvider(this, { order: 0 });
  }
}
```

Add `SessionAuth` to the `providers` of a module, the `AppModule` or your auth module.

**4. Turn Nest's body parser off.** Better Auth reads the raw body of its own routes; this module adds the parsers back for every other route. (Not with [`routes: false`](#serving-better-auths-routes-from-one-service-only), which leaves body parsing to Nest.)

```ts
// main.ts
const app = await NestFactory.create(AppModule, { bodyParser: false });
```

Every route now requires a signed-in user, as `AuthenticationModule` registers its guard globally:

```ts
import { Controller, Get } from "@nestjs/common";
import { Authenticate, CurrentSession, CurrentUser, Public } from "@nestjs/authentication";

@Controller("me")
export class MeController {
  @Get()
  me(@CurrentUser() user: User, @CurrentSession() session: Session) {
    return { user, session };
  }

  @Public()
  @Get("health")
  health() {
    return { ok: true };
  }

  @Authenticate({ optional: true })
  @Get("maybe")
  maybe(@CurrentUser() user: User | null) {
    return { signedIn: !!user };
  }
}
```

## Authentication

### Decorators

Use `@nestjs/authentication`'s decorators. This package adds none of its own.

| Decorator | Behavior |
| --- | --- |
| `@Public()` | No provider runs; `@CurrentUser()` is `null`. |
| `@Authenticate({ optional: true })` | Anonymous callers get through with `@CurrentUser()` = `null`. |
| `@Authenticate({ verifiedEmail: true })` | `403 email_unverified` until Better Auth's `user.emailVerified` is `true`. |
| `@Authenticate({ mfa: true })` | `401 mfa_required` until the session passed a second factor ([below](#second-factor-mfa)). |
| `@Authenticate({ providers: [BetterAuthSessionProvider] })` | Only these providers may authenticate the route. `ApiKeyProvider` matches `BetterAuthApiKeyProvider`. |
| `@CurrentUser()` / `@CurrentUser('email')` | Better Auth's user, plugin and additional fields included. |
| `@CurrentSession()` | Better Auth's session (`activeOrganizationId` with `organization()`, additional fields…), or what the provider that authenticated returns (see below). |

`AuthenticationContext` gives the same user and session to any provider.

### Typing `@CurrentUser()` and `@CurrentSession()`

Augment `@nestjs/authentication` once, with your instance:

```ts
import type { BetterAuthAuthenticationTypes } from "nestjs-better-auth-adapter";
import type { auth } from "./auth";

declare module "@nestjs/authentication" {
  interface AuthenticationTypes extends BetterAuthAuthenticationTypes<typeof auth> {}
}
```

### Credential providers

Extend these base classes and register your subclasses with `registry.registerProvider(this, { order })`, as in the [quick start](#quick-start). The first provider in the chain that returns a user wins.

| Base class | Credentials | `@CurrentSession()` | `super()` options | Needs |
| --- | --- | --- | --- | --- |
| `BetterAuthSessionProvider` | Session cookie; `Authorization: Bearer <session token>` with `bearer()` | Better Auth's session | | |
| `BetterAuthJwtProvider` | `Authorization: Bearer <jwt>` from `jwt()` (`/token`, `set-auth-jwt`), checked against its JWKS; socket.io's `handshake.auth.token` | The JWT claims | `{ realm?: 'api' }` | `jwt()`, and a `baseURL` |
| `BetterAuthApiKeyProvider` | `x-api-key`, or the `headers` you pass | `{ method: 'api-key', keyId, expiresAt? }` | `{ realm?: 'api', headers?: 'x-api-key' }` | `apiKey()` |
| `BetterAuthOAuthProvider` (from `/oauth-provider`) | `Authorization: Bearer` or `DPoP` access tokens from `oauthProvider()`, on routes with `@OAuthScopes()` | The token's claims (`BetterAuthOAuthAccessToken`) | `{ audience, resourceMetadata?, checkSession?, dpopReplayStore? }` ([below](#oauth-21-and-openid-connect-provider)) | `oauthProvider()`, `BetterAuthOAuthProviderModule` |

```ts
@Injectable()
export class JwtAuth extends BetterAuthJwtProvider {
  constructor(registry: AuthenticationRegistry) {
    super({ realm: "partners" });
    registry.registerProvider(this, { order: 1 });
  }
}

@Injectable()
export class ApiKeyAuth extends BetterAuthApiKeyProvider {
  constructor(registry: AuthenticationRegistry) {
    super({ realm: "partners", headers: "x-partner-key" });
    registry.registerProvider(this, { order: 2 });
  }
}
```

- A provider whose plugin is missing fails at startup, and so does the JWT one without the issuer and audience checked: set Better Auth's `baseURL` (or `BETTER_AUTH_URL`), or `jwt({ jwt: { issuer, audience } })`. The `jwt()` keys also sign the ID tokens `oauthProvider()` gives other apps. These checks run in the providers' `onModuleInit()`: a subclass with its own calls `super.onModuleInit()`.
- The session provider sends the cookies `getSession()` sets with the response, as Better Auth's own routes do: the sliding expiry (`updateAge`) reaches the browser, and the cookie cache is refreshed by your API's requests too.
- As with Nest's `SessionCookieProvider`, the session cookie on a cross-origin `POST`, `PUT`, `PATCH` or `DELETE`, or on a cross-origin WebSocket handshake, counts as no credentials (CSRF, cross-site WebSocket hijacking), unless Better Auth trusts the origin (`trustedOrigins`). A Bearer token still counts: browsers don't send it on their own.
- Bearer tokens that don't look like a JWT (two dots) are left to the session provider, so JWTs and session tokens coexist.
- The JWT provider leaves OAuth access tokens (`typ: at+jwt`) to `BetterAuthOAuthProvider`: they're signed with the same keys, and may carry the same issuer and audience, but stand for what a user granted another app, not for their session.
- The API key provider extends Nest's `ApiKeyProvider`, so `@Authenticate({ providers: [ApiKeyProvider] })` matches it, but delegates the whole check to Better Auth's `verifyApiKey`: its rate limits, remaining counts and permissions apply. Only keys owned by a user sign in. Leave `enableSessionForAPIKeys` off, or Better Auth turns the key into a session first. A refused key always answers a generic `Invalid API key`; the reason is logged at debug level.
- The `apiKey()` plugin doesn't expose its options: if you set its `apiKeyHeaders`, pass the same `headers`.
- With the `admin()` plugin, a banned user gets a 403 `banned_user` whatever they present. Better Auth itself only revokes their sessions; their JWTs, API keys and OAuth access tokens would otherwise keep working.
- A key or a JWT never satisfies `@Authenticate({ mfa: true })`.

### Adding your own checks

Each base class resolves the user in a protected `validate()` method, which your subclass can override. Without an override, it uses the default lookup.

```ts
@Injectable()
export class SessionAuth extends BetterAuthSessionProvider {
  constructor(registry: AuthenticationRegistry, private readonly accounts: AccountsService) {
    super();
    registry.registerProvider(this, { order: 0 });
  }

  // Your app's own rule; a verified email is already @Authenticate({ verifiedEmail: true }).
  protected override async validate(user: BetterAuthUser, session: BetterAuthSession) {
    return (await this.accounts.isSuspended(user.id)) ? null : user; // null: a 401
  }
}

@Injectable()
export class ApiKeyAuth extends BetterAuthApiKeyProvider {
  constructor(registry: AuthenticationRegistry, private readonly partners: PartnersService) {
    super();
    registry.registerProvider(this, { order: 2 });
  }

  protected override async validate(key: BetterAuthApiKey) {
    if (!(await this.partners.isActive(key.metadata?.partnerId))) return null;
    return super.validate(key); // keeps the owner lookup
  }
}
```

| Base class | `validate()` receives | Default |
| --- | --- | --- |
| `BetterAuthSessionProvider` | The user and session `getSession()` resolved | The user |
| `BetterAuthJwtProvider` | The verified claims | The user of `sub` |
| `BetterAuthApiKeyProvider` | The key `verifyApiKey` verified (`BetterAuthApiKey`) | Its owner, when a user |
| `BetterAuthOAuthProvider` | The verified access token's claims | The user of `sub` |

- Return `null` to refuse the credentials, or throw an `AuthenticationError` of your own. Call `super.validate()` to keep the default lookup.
- Bans (`admin()`) are checked after `validate()`, whatever it returns. For `BetterAuthOAuthProvider`, that holds for every token a user granted; a `client_credentials` token has no user to ban ([below](#admitting-client_credentials-tokens)).
- `@Authenticate({ providers: [BetterAuthSessionProvider] })` matches every subclass.

### Reading credentials from another transport

The providers read the request through protected methods, like `header()` on `@nestjs/authentication`'s providers, so a subclass can serve a transport of its own. By default they read the HTTP request (GraphQL's `context.req` included), the WebSocket handshake, and the HTTP request an `@nestjs/mcp` or `@nestjs/ai` call arrived in.

| Base class | Method | Reads |
| --- | --- | --- |
| All | `header(context, name)` (Nest's) | One request header |
| `BetterAuthSessionProvider` | `request(context)` | The headers `getSession()` reads, and the method the cross-origin check reads (`BetterAuthRequest`) |
| `BetterAuthSessionProvider` | `appendCookies(context, cookies)` | Sends the `Set-Cookie` headers `getSession()` answered with |
| `BetterAuthJwtProvider` | `token(context)` | The bearer token |
| `BetterAuthApiKeyProvider` | `apiKey(context)` | The key, from the `headers` given to `super()` |
| `BetterAuthOAuthProvider` | `requestPath(context)`, `requestTarget(context)` | The path that picks the audience; the method and URL a DPoP proof signs |
| `BetterAuthOAuthProvider` | `sendChallenge(context, challenge)` | Sends a 403 `insufficient_scope` challenge |

```ts
@Injectable()
export class SessionAuth extends BetterAuthSessionProvider {
  // ...
  protected override async request(context: ExecutionContext): Promise<BetterAuthRequest | undefined> {
    if (context.getType<string>() !== 'my-transport') return super.request(context);
    const { metadata } = context.switchToRpc().getContext();
    return { headers: { authorization: metadata.authorization } };
  }
}
```

Return `undefined` for no credentials: the guard tries the next provider.

### Errors

Every error this package throws is a class of its own, exported for exception filters. The `OAuth*` errors come from `nestjs-better-auth-adapter/oauth-provider`, the others from the package itself:

| Error | Status | Thrown when |
| --- | --- | --- |
| `BetterAuthJwtError` (a Nest `JwtError`) | 401 `invalid_token` | A `jwt()` JWT that didn't verify |
| `BetterAuthApiKeyError` | 401 `invalid_token` | An API key `apiKey()` refused |
| `BetterAuthSessionError` | 401 `invalid_session` | A session a subclass's `validate()` refused |
| `BetterAuthBannedUserError` | 403 `banned_user` | A user the `admin()` plugin banned, with any credential |
| `OAuthAccessTokenError` | 401 (`invalid_token` by default) | An OAuth access token that didn't verify, or whose user or session is gone |
| `OAuthInsufficientScopeError` | 403 `insufficient_scope` | An access token missing scopes of `@OAuthScopes()` (`scopes` lists them) |
| `OAuthAccessTokenNotAcceptedError` | 403 `access_token_not_accepted` | An access token on a route without `@OAuthScopes()` |
| `OAuthUserRequiredError` | 403 `user_required` | A `client_credentials` access token |
| `OwnedByBetterAuthError` | | A call to a store or handler step of Nest's own flows that Better Auth replaces |
| `BetterAuthConfigurationError` | | A configuration that can't work, at startup |

The credential errors are `AuthenticationError`s. Thrown by a provider, `@nestjs/authentication`'s guard turns them into Nest's own `UnauthorizedException` or `ForbiddenException`, with the original as its `cause`:

```ts
@Catch(ForbiddenException)
export class ScopeFilter implements ExceptionFilter {
  catch(exception: ForbiddenException, host: ArgumentsHost) {
    if (exception.cause instanceof OAuthInsufficientScopeError) {
      // exception.cause.scopes: what to ask the user for
    }
  }
}
```

## Second factor (MFA)

With Better Auth's `twoFactor()` plugin, a session satisfies `@Authenticate({ mfa: true })` only once it passed a second factor. The `nestjs()` plugin records that on the session (`mfaVerifiedAt`) when:

- `/two-factor/verify-totp`, `/two-factor/verify-otp` or `/two-factor/verify-backup-code` succeeds for a user who had two-factor enabled, with a confirmed authenticator for TOTP and backup codes, before the request. That covers the challenge after a password sign-in, and step-up on a session that exists already (say, a magic link sign-in that then verifies a code);
- a password sign-in from a device `twoFactor()` trusts (`trustDevice`) skips the challenge, as Better Auth allows.

Confirming a new authenticator doesn't count: it proves who holds the authenticator, not who holds the session. After enrolling, the session steps up with one more verification. Enrolling in two-factor is never enough on its own either: `twoFactor()` doesn't challenge magic link, social or OAuth sign-ins, so those sessions start without a second factor. Ask for one on the routes that need it:

```ts
@Authenticate({ mfa: true })
@Post("transfer")
transfer() {}
```

A client gets `401` with `error: "mfa_required"`, and can call a verification endpoint with its current session to step up.

`nestjs({ mfa: false })` leaves the column out; no session is reported as verified then.

## Authentication events

`@nestjs/authentication`'s `AuthenticationEvents` is the audit trail of sign-ins, sign-outs, second-factor changes, password resets and email verifications. Nest's own services publish to it; with Better Auth doing those flows, the `nestjs()` plugin publishes them instead, from Better Auth's routes, whichever client called them. Subscribe as the Nest docs describe:

```ts
@Injectable()
export class AuthenticationAudit implements OnModuleInit {
  private readonly logger = new Logger(AuthenticationAudit.name);

  constructor(private readonly events: AuthenticationEvents) {}

  onModuleInit() {
    this.events.events$.subscribe((event) => {
      if (event.type === "sign-in") this.logger.log(`${event.userId} signed in with ${event.method}`);
    });
  }
}
```

Each event also goes out on its `node:diagnostics_channel` channel (`nestjs:authentication:<type>`). They are published inside the request, before its response, so a request-scoped context (a request id, the IP) is still there. `events$` calls its subscribers synchronously: start slow work (a database write) without awaiting it, as the example's audit trail does. An event the plugin can't read (a database outage while it looks a session up) is logged, never a failed request.

| Event | Published when |
| --- | --- |
| `sign-in` | A route creates a session for someone who didn't hold it: `method` is `password` (`/sign-in/email`, `/sign-up/email`, username, phone number), `magic-link`, `oidc:<provider>` (social and generic OAuth callbacks, `/sign-in/social` with an ID token), `email-otp`, `passkey`, `impersonation`..., or the end of the `/sign-in/<method>` path. A password sign-in `twoFactor()` challenges has `mfa: 'pending'` and no `sessionId` (Better Auth replaces the session with the challenge); one from a trusted device has `mfa: 'verified'`. Sessions that replace one (two-factor verification, enabling or disabling it, `/change-password`, `/admin/stop-impersonating`) are no sign-in. |
| `sign-out` | `/sign-out`, `/revoke-session` and `/admin/revoke-user-session`, with the `sessionId` they really ended; each session `/revoke-other-sessions` ends; `everywhere: true` for `/revoke-sessions`, `/admin/revoke-user-sessions` and `/admin/ban-user`. |
| `mfa-enabled` | A TOTP authenticator confirmed by its first code, or two-factor enabled without one (`method: 'otp'`, `skipVerificationOnEnable`). `replaced` is always `false`: Better Auth refuses to enroll over a confirmed authenticator. |
| `mfa-verified` / `mfa-failed` | A TOTP or backup code (`recovery-code`) that counts as a second factor ([above](#second-factor-mfa)), or one refused. `failures` is the account lockout's count for a sign-in challenge (`1` on step-up, which Better Auth doesn't count); `locked` once it locks the account or the challenge. |
| `mfa-disabled`, `recovery-codes-generated` | `/two-factor/disable`; `/two-factor/generate-backup-codes`, with how many. |
| `password-reset-requested` / `password-reset` | `/request-password-reset` (the lowercased address, and `userId` when it has an account) and `/reset-password`; the email OTP plugin's equivalents. |
| `email-verified` | Better Auth marks an address verified: the verification link, an email OTP, a magic link to an unverified account, a provider that vouches for the address. Not an admin setting the flag. |
| `magic-link-refused` | `/magic-link/verify` turns a link down: `unknown` (Better Auth doesn't tell an expired link from a used or unknown one), or `refused` (sign-up disabled, a database hook refused the user). |

Better Auth has nothing to publish `refresh-token-reused` (its JWTs are not refresh-token families) or `session-touch-failed` for, nor `not-this-browser` refusals of magic links. Email and SMS one-time codes (`/two-factor/verify-otp`) mark the session verified but publish no `mfa-verified`: Nest's event only has `totp` and `recovery-code`. `nestjs({ events: false })` publishes nothing. Without `AuthenticationModule`, there is nothing to publish to.

## OAuth 2.1 and OpenID Connect provider

With Better Auth's [`oauthProvider()`](https://better-auth.com/docs/plugins/oauth-provider) plugin, your app is an authorization server: other apps, MCP clients among them, sign users in with it and call your API on their behalf.

```bash
npm install @better-auth/oauth-provider
```

```ts
export const auth = betterAuth({
  baseURL: "https://example.com",
  disabledPaths: ["/token"],
  plugins: [
    jwt({ disableSettingJwtHeader: true }),
    oauthProvider({
      loginPage: "/sign-in",
      consentPage: "/consent",
      scopes: ["openid", "profile", "email", "offline_access", "read:post"],
      resources: ["https://example.com/api"],
    }),
    nestjs(),
  ],
});
```

**As an authorization server**, nothing more is needed. Better Auth serves `/oauth2/*` and its discovery documents under its base path. `BetterAuthModule` also forwards the one RFC 8414 puts at the root, `/.well-known/oauth-authorization-server/api/auth`, and, when a `jwt()` issuer lives elsewhere, that issuer's documents. Your login and consent pages use Better Auth's client, as the plugin's docs describe.

**For your API to accept the tokens** (as a resource server), use the `nestjs-better-auth-adapter/oauth-provider` entrypoint. It is separate from the package's main entrypoint, so an app that doesn't accept access tokens loads none of it. Three steps:

1. Import `BetterAuthOAuthProviderModule` once, next to `BetterAuthModule`. It's global, like `BetterAuthModule`.
2. Extend `BetterAuthOAuthProvider` with your API's resource identifier as `audience`, and register it.
3. Mark the routes that take access tokens with `@OAuthScopes()`.

```ts
import { BetterAuthOAuthProviderModule } from "nestjs-better-auth-adapter/oauth-provider";

@Module({
  imports: [
    AuthenticationModule.forRoot(),
    BetterAuthModule.forRoot({ auth }),
    BetterAuthOAuthProviderModule,
  ],
  providers: [OAuthAuth],
})
export class AppModule {}
```

```ts
import { BetterAuthOAuthProvider } from "nestjs-better-auth-adapter/oauth-provider";

@Injectable()
export class OAuthAuth extends BetterAuthOAuthProvider {
  constructor(registry: AuthenticationRegistry) {
    super({
      audience: "https://example.com/api",
      resourceMetadata: { scopes_supported: ["read:post"] },
    });
    registry.registerProvider(this, { order: 3 });
  }
}
```

```ts
import { type BetterAuthOAuthAccessToken, OAuthScopes } from "nestjs-better-auth-adapter/oauth-provider";

@Controller("api/posts")
export class PostsController {
  @OAuthScopes("read:post")
  @Get()
  list(@CurrentUser() user: User, @CurrentSession() token: BetterAuthOAuthAccessToken) {
    // token.azp is the app the user granted access to; token.scopes, what for
  }
}
```

- **Verification.** `BetterAuthOAuthProvider` verifies JWT access tokens with the plugin's own resource client. It checks:
  - the signature, against the `jwt()` keys read in-process;
  - the issuer, the audience and the expiry;
  - the RFC 9068 type (`at+jwt`);
  - for sender-constrained tokens (`Authorization: DPoP`), the DPoP proof, each recorded once in Better Auth's storage so every instance sees it.
- **Which tokens.** Clients get JWT access tokens by requesting the `resource`. Without one, the plugin issues opaque tokens meant for its `userinfo` endpoint, which the API refuses.
- **Scopes.** A route accepts access tokens only with `@OAuthScopes()`, and only when they carry every scope it lists. `@OAuthScopes()` with no scope accepts any token issued for this API.
  - Elsewhere, an access token gets a 403 (`access_token_not_accepted`): a token a user granted another app never stands for their whole session.
  - A missing scope gets a 403 with RFC 6750's `insufficient_scope` challenge naming it.
  - The session, `jwt()` JWTs and API keys work as before on these routes.
  - A scope the plugin doesn't issue (its `scopes`, or their defaults) fails at startup, naming the class and the method: no token could carry it, so a typo (`read:posts` for `read:post`) would otherwise only show as 403s.
  - `OAuthScopes` is also the key `Reflector` reads the scopes by, for a guard of your own where `AuthenticationGuard` doesn't run, or a test holding the declarations against something else. A method's scopes replace its class's, as for the provider:

    ```ts
    const scopes = reflector.getAllAndOverride<readonly string[] | undefined>(OAuthScopes, [
      context.getHandler(),
      context.getClass(),
    ]);
    ```
- **The user.** `@CurrentUser()` is the user who granted the token. `client_credentials` tokens have no user and get a 403 (`user_required`), unless your provider admits them ([below](#admitting-client_credentials-tokens)).
- **Revocation.** As with introspection, a token stops working once the session it was granted from ends (sign-out, revoked session). `checkSession: false` skips that lookup, and tokens then pass until they expire.
- **Discovery for clients.** 401s point clients to `/.well-known/oauth-protected-resource/api` (RFC 9728), and MCP clients find the authorization server through it. Each provider builds its document at startup and hands it to `BetterAuthOAuthProviderModule`, which serves it to any origin, one per `audience`. A provider fails at startup without the module.
- **Several audiences.** An API that is the resource server of more than one identifier (its REST API and its MCP endpoint, a new domain and an old one) lists them all: `super({ audience: ["https://example.com/api", "https://example.com/mcp"] })`. One provider then accepts a token whose `aud` has any of them, and serves a metadata document for each. Its challenges point to the audience whose path the request's path is under (the longest match), else to the first. Audiences whose documents would share a path (`https://a.example/api` and `https://b.example/api`) fail at startup, unless `resourceMetadata: false`.
  - Several providers with one audience each don't do the same: the chain stops at the first that refuses a token, so a token for the second audience never reaches its provider.
  - Don't list another service's audience so that it can pass its callers' tokens on to you: an MCP server must not forward the tokens it receives. Have the client request a token for both resources (RFC 8707's `resource`, repeated), whose `aud` then has both.
- **With secondary storage.** `oauthProvider()` then needs `session.storeSessionInDatabase: true`, and fails at startup without it: it reads sessions from the database, and so does `checkSession`. See [scaling](#scaling-secondary-storage-and-the-cookie-cache).
- **Behind a proxy.** DPoP proofs sign the request's URL, so set Express's or Fastify's `trust proxy` for the scheme and host to be the client's.

#### Admitting `client_credentials` tokens

A `client_credentials` token is a client calling for itself: its `sub` is its `azp`, and no user stands behind it. To admit them, return a principal for the client from `validate()`, and type it with `BetterAuthOAuthProvider`'s type parameter. `@CurrentUser()` is then `BetterAuthUser | TPrincipal`:

```ts
export type ApiClient = { kind: "client"; clientId: string };

@Injectable()
export class MachineAuth extends BetterAuthOAuthProvider<ApiClient> {
  constructor(registry: AuthenticationRegistry) {
    super({ audience: "https://example.com/api" });
    registry.registerProvider(this, { order: 3 });
  }

  protected override async validate(claims: JwtClaims) {
    if (this.isClientCredentials(claims))
      return { kind: "client" as const, clientId: String(claims.azp) };
    return super.validate(claims); // users' tokens, as before
  }
}
```

```ts
@OAuthScopes("sync:orders")
@Post("orders/sync")
sync(@CurrentUser() caller: User | ApiClient, @CurrentSession() token: BetterAuthOAuthAccessToken) {
  if ("kind" in caller) {
    // a client: token.azp, token.scopes
  }
}
```

- `@OAuthScopes()` still applies: a client's token passes only with the route's scopes, those in the client's `client_credentials_scopes`.
- A client is not a user. Give the principal a discriminant (`kind` above), and in the policies of routes that admit clients, check it before reading user fields, and before the [access control policies](#policies-backed-by-better-auths-access-control)' helpers, which take a Better Auth user.
- Bans still apply to every token a user granted, whatever principal `validate()` builds for them. A principal without the user's `banned` field costs a second lookup to check it; keep `super.validate()`'s fields (`{ ...user, kind: "user" }`) to avoid it.
- A subclass that doesn't override `validate()` keeps refusing them with `user_required`. To admit them on some routes only, register the subclass after the one that refuses them, and pick it with `@Authenticate({ providers: [MachineAuth] })` on those routes, with `resourceMetadata: false` if both have the same `audience`.

## Module configuration

### `forRootAsync()`

`forRootAsync()` takes `useFactory`, `useClass` or `useExisting`, with `imports` and `inject`, like Nest's own modules. An options class, like `GqlOptionsFactory` in `@nestjs/graphql`, keeps the auth config next to what it injects (`ConfigService`, Nest's `PasswordHasher`…).

The Better Auth CLI needs an `auth` export it can load on its own, so keep a plain config file for it as well (sharing the options object is the simplest way).

The easiest way to share it is a **factory function**: it builds the Better Auth instance from arguments, the CLI's file calls it with environment variables, and Nest calls it with injected services. Three small files:

```text
src/auth/
├── create-auth.ts   the factory: the whole Better Auth config, in one place
├── auth.ts          for the Better Auth CLI only
└── auth.options.ts   for Nest: BetterAuthOptionsFactory
```

**1. The factory** (`src/auth/create-auth.ts`). Everything that differs between the CLI and the app is an argument:

```ts
import type { PasswordHasher } from "@nestjs/authentication";
import { betterAuth } from "better-auth";
import { twoFactor } from "better-auth/plugins";
import { betterAuthPassword, nestPasswordHasher, nestjs } from "nestjs-better-auth-adapter/plugin";
import { Pool } from "pg";

export interface CreateAuthOptions {
  databaseUrl: string;
  secret: string;
  baseURL: string;
  /** Nest's PasswordHasher. The CLI never hashes passwords, so it can leave it out. */
  hasher?: PasswordHasher;
}

export function createAuth({ databaseUrl, secret, baseURL, hasher }: CreateAuthOptions) {
  return betterAuth({
    database: new Pool({ connectionString: databaseUrl }),
    secret,
    baseURL,
    emailAndPassword: {
      enabled: true,
      password: hasher ? betterAuthPassword(hasher) : nestPasswordHasher(),
    },
    plugins: [twoFactor(), nestjs()],
  });
}

/** The type of your instance, plugins included: use it to type BetterAuthService and @CurrentUser(). */
export type Auth = ReturnType<typeof createAuth>;
```

**2. The CLI's file** (`src/auth/auth.ts`). It only calls the factory, and is never imported by the app:

```ts
import { createAuth } from "./create-auth";

// Read by `npx auth generate|migrate --config src/auth/auth.ts`.
export const auth = createAuth({
  databaseUrl: process.env.DATABASE_URL ?? "",
  secret: process.env.BETTER_AUTH_SECRET ?? "",
  baseURL: process.env.BETTER_AUTH_URL ?? "http://localhost:3000",
});
```

**3. The options class** (`src/auth/auth.options.ts`). Nest injects what the factory needs:

```ts
import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PasswordHasher } from "@nestjs/authentication";
import type { BetterAuthOptionsFactory } from "nestjs-better-auth-adapter";
import { createAuth } from "./create-auth";

@Injectable()
export class AuthConfig implements BetterAuthOptionsFactory {
  constructor(
    private readonly config: ConfigService,
    private readonly hasher: PasswordHasher, // provided by AuthenticationModule
  ) {}

  createBetterAuthOptions() {
    return {
      auth: createAuth({
        databaseUrl: this.config.getOrThrow("DATABASE_URL"),
        secret: this.config.getOrThrow("BETTER_AUTH_SECRET"),
        baseURL: this.config.getOrThrow("BETTER_AUTH_URL"),
        hasher: this.hasher,
      }),
    };
  }
}
```

**4. The module:**

```ts
@Module({
  imports: [
    ConfigModule.forRoot(),
    AuthenticationModule.forRoot(),
    BetterAuthModule.forRootAsync({ imports: [ConfigModule], useClass: AuthConfig }),
  ],
})
export class AppModule {}
```

Then generate or apply the schema with Better Auth's CLI (the `auth` package; `@better-auth/cli` is its old name), with the same environment variables set as for the app:

```bash
npx auth@latest generate --config src/auth/auth.ts   # writes the schema for your ORM, or SQL
npx auth@latest migrate --config src/auth/auth.ts    # or applies it to the database (Kysely adapter, e.g. a pg Pool)
```

In a CommonJS project (`nest new`), Node may print "Reparsing as ES module…" while the CLI loads the file: it's a harmless warning.

Type everything from the factory's `Auth` type:

```ts
import type { BetterAuthAuthenticationTypes } from "nestjs-better-auth-adapter";
import type { Auth } from "./auth/create-auth";

declare module "@nestjs/authentication" {
  interface AuthenticationTypes extends BetterAuthAuthenticationTypes<Auth> {}
}

// and in a service:
constructor(private readonly betterAuth: BetterAuthService<Auth>) {}
```

### `BetterAuthService`

The instance, injectable anywhere, for server-side calls:

```ts
constructor(private readonly betterAuth: BetterAuthService<typeof auth>) {}

listSessions(headers: Headers) {
  return this.betterAuth.api.listSessions({ headers });
}
```

`authenticate()` answers what `@Authenticate()` would see for a request outside Nest's guard, a Better Auth hook's above all: `{ user, session }`, with `mfa: "verified"` once the session passed a second factor, or `null`. The app's own checks on Better Auth's routes then follow the same rule as Nest's guard:

```ts
@Hook()
@Injectable()
export class StepUpHooks {
  constructor(private readonly betterAuth: BetterAuthService) {}

  @BeforeHook("/admin/ban-user")
  async requireSecondFactor(ctx: AuthHookContext) {
    const signedIn = await this.betterAuth.authenticate(ctx);
    if (signedIn && signedIn.mfa !== "verified")
      throw new APIError("UNAUTHORIZED", { code: "MFA_REQUIRED" });
  }
}
```

- **One read per request.** Given a hook's context, it reuses the session Better Auth already resolved for the request, and leaves the one it resolves for the endpoint, which then doesn't read it again. Better Auth's sensitive routes, the `admin()` ones and `revoke-other-sessions` among them, read the session again on purpose, from its store.
- **`bearer()` tokens count.** It goes through `getSession()`. `getSessionFromCtx(ctx)` in a before hook misses them, since `bearer()` turns the token into a cookie only after the before hooks.
- **Not a provider run.** A subclass's `validate()`, the ban check and the cross-origin check don't run: Better Auth's routes check their own callers. `authenticate(headers)` takes plain headers elsewhere.

### Routes, CORS and body parsing

- Better Auth's routes are served where Better Auth's own router expects them: the path of its `baseURL` (the option, or `BETTER_AUTH_URL`) when it has one, else its `basePath` (`/api/auth` by default). To move them, change Better Auth's config, `betterAuth({ basePath: "/auth" })`: the module follows. The path is normalized (`auth/` serves `/auth`), kept outside any global prefix, and can't be `/`. `BetterAuthService.basePath` gives it back, to build links to Better Auth's endpoints.
- Better Auth's routes answer CORS for the origins Better Auth trusts, with credentials, matched by Better Auth itself: its `trustedOrigins` with their wildcards, `BETTER_AUTH_TRUSTED_ORIGINS`, its `baseURL`. Express and Fastify behave the same. CORS for your own routes is yours, with `app.enableCors()`. `trustedOriginsCors: false` leaves Better Auth's routes to it too. A function `trustedOrigins` needs `trustedOriginsCors: false`.
- Body parsing for the other routes is configurable, Express and Fastify alike:

```ts
BetterAuthModule.forRoot({
  auth,
  bodyParser: {
    json: { limit: "2mb" },
    urlencoded: { enabled: false },
    rawBody: true, // req.rawBody, for webhook signatures
  },
});
```

- With `jwt()`, its JWKS (`/api/auth/jwks`, or its `jwks.jwksPath`) is sent with a `Cache-Control`, which Better Auth doesn't send: it's the document every resource server fetches before it accepts a token, and a CDN can then serve it while the issuer is cold or down. By default, the policy `oauthProvider()` sends with the discovery documents pointing at it, `public, max-age=15, stale-while-revalidate=15, stale-if-error=86400`. `jwksCacheControl` replaces it, `false` sends none. It only fills a missing header, on a 200: if Better Auth sends its own, it wins. With `jwks.remoteUrl`, the JWKS is published there and not served here: there's nothing to send it with, and a `jwksCacheControl` policy fails at startup.

```ts
BetterAuthModule.forRoot({
  auth,
  jwksCacheControl: "public, max-age=300, stale-while-revalidate=86400, stale-if-error=86400",
});
```

- `middleware` wraps Better Auth's handler, e.g. for MikroORM's `RequestContext`:

```ts
BetterAuthModule.forRoot({
  auth,
  middleware: (req, res, next) => RequestContext.create(orm.em, next),
});
```

### Serving Better Auth's routes from one service only

In a platform where several Nest services share one Better Auth (one database, one secret, one secondary storage), one of them serves its routes and the others only authenticate their callers: a GraphQL gateway, a worker, an agent runtime. On those, `routes: false` mounts nothing, so sign-up and sign-in aren't answered on a host never meant to answer them:

```ts
BetterAuthModule.forRoot({ auth, routes: false });
```

```ts
// main.ts: Nest's own body parser stays on (rawBody: true works again)
const app = await NestFactory.create(AppModule);
```

- Nothing is mounted: not Better Auth's handler, its CORS, the body parsers, nor `oauthProvider()`'s discovery documents (the authorization server's, served by the service with the routes). The base path isn't excluded from the global prefix either.
- The credential providers, `@Hook()` / `@DatabaseHook()`, the Nest handlers, `AuthenticationEvents` and `BetterAuthService` work the same: they call Better Auth in-process. `BetterAuthService.basePath` still gives the path of the routes, for links to the service that serves them.
- `BetterAuthOAuthProviderModule` still serves the RFC 9728 resource metadata: an app that accepts access tokens is a resource server, whichever service issues them.
- `bodyParser`, `middleware` and a `jwksCacheControl` policy only apply to the routes: with `routes: false`, they fail at startup rather than being ignored.

## Scaling: secondary storage and the cookie cache

What each credential costs per request, with Better Auth's defaults:

| Credential | Per request |
| --- | --- |
| Session cookie, or a session's Bearer token | Better Auth's `getSession()`: a database read for the session and its user |
| `jwt()` JWT | The signature, checked in-process, then the user, read by primary key |
| API key | `verifyApiKey`: its read, and the writes its rate limit and remaining count need; then the owner, by primary key |
| OAuth access token | The signature, checked in-process, then the user and (`checkSession`) the session, by primary key, in parallel |

The session is the credential most requests carry, and Better Auth has two options that take it off the database: **secondary storage** and the **cookie cache**. Both are Better Auth's own options, and the module and the providers work the same with them. Use secondary storage, on Redis, first. Add a short cookie cache on top when the Redis round trip still matters.

### Secondary storage, on Redis

With `secondaryStorage`, Better Auth keeps these in a key-value store, shared by every instance of your API:

- **Sessions.** `getSession()` reads them from Redis instead of the database. A sign-out, a revoked session or a ban (`admin()` deletes the user's sessions) takes effect on the next request, on every instance. When Better Auth updates a user, it updates the copy stored with their sessions too.
- **Rate limits.** Better Auth counts them in the secondary storage once there is one. Without it, each process counts its own in memory, so N instances allow N times the limit.
- **Single-use values.** Verification tokens, and the DPoP proofs `BetterAuthOAuthProvider` records.
- **API keys**, when you choose `apiKey({ storage: "secondary-storage" })`.

Users, accounts and organizations stay in the database.

The storage is Better Auth's [`@better-auth/redis-storage`](https://better-auth.com/docs/concepts/database#secondary-storage), on [`ioredis`](https://github.com/redis/ioredis), the client Nest's own [Redis transport](https://docs.nestjs.com/microservices/redis) uses. Nest's [caching](https://docs.nestjs.com/techniques/caching) chapter puts Redis behind `CacheModule` (`@keyv/redis`), but that cache can't be Better Auth's storage. Better Auth needs an atomic `increment` (rate limits) and an atomic `getAndDelete` (single-use tokens), and `cache-manager` has neither. Both can share one Redis server, since Better Auth prefixes its keys with `better-auth:`.

```bash
npm install @better-auth/redis-storage ioredis
```

The Nest way to give Better Auth a client is the same as for any other: a [custom provider](https://docs.nestjs.com/fundamentals/custom-providers) in a global module, which also closes the connection on shutdown. Here it sits next to the database, registered with Nest's [`@nestjs/drizzle`](https://docs.nestjs.com/data/drizzle), and builds on the factory of [`forRootAsync()`](#forrootasync). The [example app](example) runs this setup.

**1. The Redis client** (`src/redis/redis.module.ts`):

```ts
import { Global, Inject, Module, type OnApplicationShutdown } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { Redis } from "ioredis";

export const REDIS = Symbol("REDIS");
export const InjectRedis = () => Inject(REDIS);

@Global()
@Module({
  providers: [
    {
      provide: REDIS,
      inject: [ConfigService],
      useFactory: (config: ConfigService) => new Redis(config.getOrThrow("REDIS_URL")),
    },
  ],
  exports: [REDIS],
})
export class RedisModule implements OnApplicationShutdown {
  constructor(@InjectRedis() private readonly redis: Redis) {}

  async onApplicationShutdown() {
    await this.redis.quit();
  }
}
```

**2. The factory** (`src/auth/create-auth.ts`) takes the database and the client:

```ts
import { redisStorage } from "@better-auth/redis-storage";
import type { PasswordHasher } from "@nestjs/authentication";
import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import type { NodePgDatabase } from "drizzle-orm/node-postgres";
import type { Redis } from "ioredis";

export interface CreateAuthOptions {
  db: NodePgDatabase;
  /** Left out by the Better Auth CLI, which only reads the schema. */
  redis?: Redis;
  secret: string;
  baseURL: string;
  hasher?: PasswordHasher;
}

export function createAuth({ db, redis, secret, baseURL, hasher }: CreateAuthOptions) {
  return betterAuth({
    database: drizzleAdapter(db, { provider: "pg" }),
    secondaryStorage: redis && redisStorage({ client: redis }),
    session: {
      // Optional, see below: sessions in the database too (needed by oauthProvider()).
      // storeSessionInDatabase: true,
      cookieCache: { enabled: true, maxAge: 60 },
    },
    // ...
  });
}
```

The CLI's `auth.ts` passes its own `drizzle(process.env.DATABASE_URL)` and no `redis`.

**3. The options class** injects them, as it injects `ConfigService`:

```ts
import { InjectDrizzle } from "@nestjs/drizzle";
import { InjectRedis } from "../redis/redis.module";

@Injectable()
export class AuthConfig implements BetterAuthOptionsFactory {
  constructor(
    private readonly config: ConfigService,
    private readonly hasher: PasswordHasher,
    @InjectDrizzle() private readonly db: NodePgDatabase,
    @InjectRedis() private readonly redis: Redis,
  ) {}

  createBetterAuthOptions() {
    return {
      auth: createAuth({
        db: this.db,
        redis: this.redis,
        secret: this.config.getOrThrow("BETTER_AUTH_SECRET"),
        baseURL: this.config.getOrThrow("BETTER_AUTH_URL"),
        hasher: this.hasher,
      }),
    };
  }
}
```

**4. The module:**

```ts
import { DrizzleModule } from "@nestjs/drizzle";
import { drizzle } from "drizzle-orm/node-postgres";

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    DrizzleModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        drizzle,
        connection: config.getOrThrow("DATABASE_URL"),
      }),
    }),
    RedisModule,
    AuthenticationModule.forRoot(),
    BetterAuthModule.forRootAsync({ useClass: AuthConfig }),
  ],
})
export class AppModule {}
```

Keep in mind:

- **Sessions live only in Redis by default.** Persist it (AOF or RDB): losing it signs everyone out. `session.storeSessionInDatabase: true` writes them to the database as well, for an audit trail or listings in SQL, at the cost of that write.
- **`oauthProvider()` needs `storeSessionInDatabase: true`** with a secondary storage, and fails at startup without it.
- **The other credentials still read the user from the database.** The JWT, API key and OAuth providers read it by primary key. To cache it, override their `validate()`.

### The cookie cache

`session.cookieCache` signs the session and its user into a cookie, valid for `maxAge` seconds. While it is fresh, `getSession()` reads neither Redis nor the database. The session provider sends the refreshed cookie back with your API's responses too, as Better Auth's routes do.

The cost is staleness. For up to `maxAge`, a request with the cached cookie doesn't see:

- a session revoked elsewhere, or a sign-out on another device (signing out in the same browser clears the cookie);
- a ban;
- a changed role.

So keep `maxAge` short, a minute to five: it is how long a ban can lag. `BetterAuthPermissionPolicy` doesn't trust a cached role: with the cookie cache on, it lets Better Auth read the current one.

## Hooks

Better Auth's request and database hooks can be Nest providers, with dependency injection. They run through the `nestjs()` plugin, so the config needs no `hooks` or `databaseHooks`.

```ts
import { Injectable } from "@nestjs/common";
import { AfterHook, BeforeHook, Hook, type AuthHookContext } from "nestjs-better-auth-adapter";

@Hook()
@Injectable()
export class SignUpHook {
  constructor(private readonly audit: AuditService) {}

  @BeforeHook("/sign-up/email")
  async validate(ctx: AuthHookContext) {
    // throw an APIError to refuse, as in any Better Auth hook
  }

  @AfterHook("/sign-in/email")
  async log(ctx: AuthHookContext) {
    await this.audit.signIn(ctx.context.newSession?.user.id);
  }
}
```

Without a path, a hook runs on every route. What a hook returns is what a Better Auth hook returns: an `@AfterHook` value replaces the response.

```ts
import { AfterCreate, BeforeCreate, DatabaseHook } from "nestjs-better-auth-adapter";

@DatabaseHook()
@Injectable()
export class UserHooks {
  @BeforeCreate("user")
  normalize(user: { email: string }) {
    return { data: { email: user.email.toLowerCase() } };
  }

  @AfterCreate("user")
  async welcome(user: { id: string }) {
    await this.mailer.welcome(user.id);
  }
}
```

`@BeforeCreate`, `@AfterCreate`, `@BeforeUpdate`, `@AfterUpdate`, `@BeforeDelete` and `@AfterDelete` take `user`, `session`, `account` or `verification`. `before` hooks chain: `false` from any of them cancels the write, `{ data }` changes it for the next hook and the write. Better Auth runs plugin database hooks first, so these run before the `databaseHooks` of your config.

## Nest handlers and `PasswordHasher`

All optional. Extend the Better Auth handler and register it in `AuthenticationRegistry`: it plugs itself into Better Auth. Leave it out and Better Auth uses its own config.

### Email handlers

`@nestjs/authentication`'s email features, with Better Auth creating and checking the tokens. Configure the feature with where the link goes (Better Auth's own endpoint, or a page of yours: [below](#migrating-from-better-auths-callbacks)), extend the matching Better Auth handler, implement `send()`, and register it from your constructor, as any Nest handler. Each base class takes `AuthenticationRegistry` and `BetterAuthService`, and plugs itself into Better Auth at startup (`onModuleInit`) when it is the registered handler; it puts Better Auth's own callback back when the app closes.

```ts
AuthenticationModule.forRoot({
  // The frontend's page, which receives `?token=…`.
  passwordReset: { url: "https://app.example.com/reset-password" },
})
```

```ts
@Injectable()
export class ResetMailer extends BetterAuthPasswordResetHandler {
  constructor(registry: AuthenticationRegistry, betterAuth: BetterAuthService, private readonly mailer: Mailer) {
    super(registry, betterAuth);
    registry.registerHandler("passwordReset", this);
  }

  send({ user, url }: BetterAuthPasswordResetLink) {
    return this.mailer.send(user.email, `${user.name}, reset your password`, url);
  }
}
```

Better Auth's callback sends through the handler registered for the feature, asked at each call. The link is the feature's `url` with Better Auth's token in `?token=`, plus the query Better Auth put on its own link (`callbackURL`…). A page of yours hands the token to Better Auth:

| Base class | Feature (`url`) | Replaces | The page calls | Requires in the Better Auth config |
| --- | --- | --- | --- | --- |
| `BetterAuthPasswordResetHandler` | `passwordReset` | `emailAndPassword.sendResetPassword` | `POST {basePath}/reset-password` with `{ token, newPassword }` (`authClient.resetPassword`) | `emailAndPassword: { enabled: true }` |
| `BetterAuthEmailVerificationHandler` | `emailVerification` | `emailVerification.sendVerificationEmail` | `GET {basePath}/verify-email?token=…` (`authClient.verifyEmail`) | `emailVerification: {}` |
| `BetterAuthMagicLinkHandler` | `magicLink` | `magicLink({ sendMagicLink })` | `GET {basePath}/magic-link/verify?token=…` (`authClient.magicLink.verify`) | `magicLink({ sendMagicLink: fromNestHandler })` |

- **What Better Auth gave its callback.** `send()` gets it on the link, besides Nest's fields (`email`, `url`, `expiresAt`):

  | Link | Fields |
  | --- | --- |
  | `BetterAuthPasswordResetLink`, `BetterAuthEmailVerificationLink` | `user` (whole, with your additional fields: no lookup to address the mail by name), `token`, `request` |
  | `BetterAuthMagicLink` | `token`, `metadata` (the client's `signIn.magicLink({ metadata })`), `request`, `context` (the plugin's endpoint context, `sendMagicLink`'s second argument) |

  `request` is the request that asked for the link, none when the app called `auth.api` without one. `token` is also in `url`, and it signs the user in (or resets their password) while it's valid: to key records by it, store a hash of it. A handler typed with Nest's own link types keeps working.
- **What Better Auth decides.** How long a link lasts is Better Auth's config (`resetPasswordTokenExpiresIn`, `emailVerification.expiresIn`, `magicLink({ expiresIn })`): the features' `ttl`, and `magicLink`'s `bindToBrowser` and `cookie`, fail at startup rather than be ignored.
- **Nest's own flows are refused.** Better Auth finds the accounts, stores the passwords and verifies the addresses: the rest of Nest's contract (`findUser()`, `updatePassword()`, `markVerified()`, `resolveUser()`) throws, and so does `PasswordResetService`, `EmailVerificationService` or `MagicLinkService` if something calls them. `isVerified()` keeps Nest's default, Better Auth's `user.emailVerified`, for `@Authenticate({ verifiedEmail: true })`.
- **Stores.** These features name stores (`sessions`, `emailTokens`, `magicLinks`) Nest requires in production. `BetterAuthModule` registers them with `AuthenticationStorage`, for the configured features only, refusing every call: Better Auth keeps the sessions and the links, so no in-memory copy runs on the side. `sessions` is left to you when Nest's own `session` feature is on.
- **Swapping a handler.** A wrapper or a test double extending the same base class takes over with `registry.registerHandler("passwordReset", this, { replace: true })`, from its constructor (the registry locks once the app has initialized): the registered one plugs itself in. A plain Nest handler registered for these features fails at startup, as Better Auth would never call it.
- `fromNestHandler` (from `nestjs-better-auth-adapter/plugin`) fills a callback Better Auth's types require; startup fails without a registered handler to replace it. A handler replaces a callback the config defines, and says so in the logs.

#### Migrating from Better Auth's callbacks

Moving a callback to a handler doesn't change the links in your emails, nor need new pages, for two of the three features: point `url` at Better Auth's own endpoint, and the link is the one Better Auth would have sent (its query, `callbackURL` and the others, rides along).

| Feature | `url` | Link sent |
| --- | --- | --- |
| `emailVerification` | `https://example.com/api/auth/verify-email` | `/api/auth/verify-email?callbackURL=…&token=…`: Better Auth verifies the address and redirects, as before |
| `magicLink` | `https://example.com/api/auth/magic-link/verify` | `/api/auth/magic-link/verify?callbackURL=…&token=…`: Better Auth signs the user in and redirects, as before |
| `passwordReset` | your reset page | Better Auth's own link has the token in its path (`/reset-password/:token`), which `?token=` can't reproduce: the page reads `?token=` and posts it with the new password to `/reset-password` (`authClient.resetPassword`, as better-auth-ui's reset view does) |

What the callback did besides sending the mail moves to `send()` too: it gets the same data, on the link ([above](#email-handlers)).

### `OidcAccountResolver`

Better Auth signs users in with its `socialProviders` and decides which user an identity belongs to: the provider account's owner, else, as `account.accountLinking` allows, the user with that address (by default only when the provider and the user both verified it, which stops account pre-hijacking). Extend `BetterAuthOidcAccountResolver` and register it as the `oidc` handler: it plugs itself into Better Auth's own gate, `user.validateUserInfo` (after the config's own one, if any), and confirms or refuses that choice. Out of the box it confirms it: add the app's rules in `validate()`, as on the credential providers.

```ts
AuthenticationModule.forRoot({
  oidc: {
    // Better Auth's callback: the redirect URI registered with each provider.
    callbackUrl: "https://api.example.com/api/auth/callback/:provider",
    // Better Auth's socialProviders sign users in: Nest's OIDC client serves none.
    providers: () => null,
  },
})
```

```ts
@Injectable()
export class AccountLinker extends BetterAuthOidcAccountResolver {
  constructor(registry: AuthenticationRegistry, betterAuth: BetterAuthService) {
    super(registry, betterAuth);
    registry.registerHandler("oidc", this);
  }

  // The user Better Auth chose, looked up: refuse it with `null`.
  protected override validate(user: BetterAuthUser, profile: OidcProfile, context: OidcResolveContext) {
    return user.role === "admin" ? null : user;
  }
}
```

| Method | Default | Override it to |
| --- | --- | --- |
| `validate(user, profile, context)` | The user | Add the app's rules: return `null`, or throw |
| `findUserId(profile)` | The provider account's owner, else the address's user | Look the user up in a repository of your own |
| `findUser(id)` | Better Auth's user | Load it from a repository of your own |
| `resolveUser(profile, tokens, context)` | `context.linkTo`, else `findUserId()`, loaded with `findUser()`, then `validate()` | Replace the whole flow (Nest's own contract) |

- **When it's asked.** Before Better Auth attaches an identity to an existing user: a sign-in with a linked provider (every time, with the provider's fresh profile), a link by email, and a signed-in user connecting a provider (`context.linkTo`, read from Better Auth's OAuth state). A new identity creates a new user, which Better Auth's sign-up options govern (`disableImplicitSignUp`, `disableSignUp`): the resolver isn't asked.
- **What it returns.** The user Better Auth chose, as `{ id }`, confirms; `null`, or another user, refuses: the browser lands on Better Auth's error URL with `error=account_link_refused`, and nothing is stored.
- **What it receives.** `profile.claims` is the provider's raw profile, and `subject` its `sub` (or `id`). Better Auth's gate runs before it stores the provider's tokens, so `tokens.accessToken` is empty.
- **The `oidc` option.** `@nestjs/authentication` requires it with a registered handler. `callbackUrl` must be Better Auth's callback route; `providers` must be a function, as Nest's own OIDC client would sign users in next to Better Auth; its other options have no effect and fail at startup. `BetterAuthModule` registers the feature's stores (`sessions`, `oidcStates`), refusing every call.
- With a `validateUserInfo` gate, Better Auth refuses `internalAdapter.createUser()` outside an endpoint (`validation_context_missing`): create users through `auth.api`.

### `PasswordHasher`

Nest's `PasswordHasher` (scrypt at OWASP settings, constant-time checks, NFKC normalization) can hash Better Auth's passwords, with its cost set once in `AuthenticationModule.forRoot({ password })`:

- `betterAuthPassword(hasher)` where the hasher can be injected (`forRootAsync`, above);
- `nestPasswordHasher()` in a config built before Nest exists (`forRoot`, the CLI's file); the module binds it at startup.

```ts
betterAuth({
  emailAndPassword: { enabled: true, password: nestPasswordHasher() },
  plugins: [nestjs()],
});
```

Existing Better Auth hashes keep verifying (`legacyHashes: false` turns that off). They are upgraded the next time Better Auth verifies the password (any sign-in, challenged by two-factor or not, or a password change), as are hashes made with an older cost. The upgrade is one conditional write, through the `nestjs()` plugin: a hash changed meanwhile is left alone, and a failed upgrade is logged without failing the sign-in.

### Your own callbacks: `BetterAuthConfigAugmenter`

For Better Auth callbacks no Nest handler covers (`user.changeEmail.sendChangeEmailConfirmation`, `user.deleteUser.sendDeleteAccountVerification`, `user.deleteUser.beforeDelete`…), plug a provider of yours in with `BetterAuthConfigAugmenter`, which the handlers above use too. It's typed from the instance's type: the paths are the callbacks of the sections it configures, and each callback takes the signature Better Auth declares.

```ts
@Injectable()
export class AccountMails implements OnModuleInit, OnModuleDestroy {
  readonly #config: BetterAuthConfigAugmenter<typeof auth>;

  constructor(betterAuth: BetterAuthService<typeof auth>, private readonly mailer: Mailer) {
    this.#config = new BetterAuthConfigAugmenter(betterAuth.instance)
      .replace("user.changeEmail.sendChangeEmailConfirmation", async ({ user, newEmail, url }) =>
        this.mailer.send(user.email, `Confirm the change to ${newEmail}`, url),
      )
      .replace("user.deleteUser.sendDeleteAccountVerification", async ({ user, url }) =>
        this.mailer.send(user.email, "Confirm the deletion of your account", url),
      );
  }

  onModuleInit() {
    return this.#config.apply();
  }

  onModuleDestroy() {
    this.#config.restore();
  }
}
```

- **In order.** `replace()`, `wrap()` and `plugin()` queue their changes, in the order they're called; `apply()` makes them, once Better Auth built its context. `restore()` puts back what they replaced, last first, so two changes of one callback undo cleanly.
- **`wrap(path, (original) => callback)`** runs code around the config's own callback (`undefined` when it has none), rather than replace it.
- **`plugin(id, (plugin) => …)`** reaches a plugin's callbacks, typed as the plugin declares its options: `plugin("magic-link", (magicLink) => magicLink.replace("sendMagicLink", …))`. The id must be one of the instance's plugins.
- **Where Better Auth reads them.** Better Auth copies its options into its context when the instance is created, and its endpoints read that copy: changes go to both, and to the context alone for a section only it has (one a plugin's `init()` added). Top-level options are refused, as are `database`, `secondaryStorage`, `logger` and `plugins`, which aren't config.
- **Fails rather than does nothing.** A section the instance doesn't configure fails at `apply()`, naming it: a callback doesn't turn its feature on (`user.deleteUser` needs `enabled: true`). `{ create: true }` creates the sections, for those without a feature to turn on (`user` for `user.validateUserInfo`). So does a key holding something else than a callback, and a path through `__proto__`.
- **Types.** With `typeof auth` (or `BetterAuthService<typeof auth>`), only the configured sections' paths are offered; with `Auth`, every section's, still typed by Better Auth's schema. `BetterAuthCallbackPath<Options>` and `BetterAuthCallbackAt<Options, Path>` give them to your own code.

## Authorization

Requires `@nestjs/authorization`. Import `AuthorizationModule.forRoot()`: it denies every route without `@Can()` or `@Can.Anyone()`.

### Policies backed by Better Auth's access control

`BetterAuthACPolicy(resource, config)` builds a policy class whose abilities are checked with the `admin()` plugin's access control. `BetterAuthOrganizationACPolicy(resource, config)` builds one checked with the `organization()` plugin's, for the member's role in an organization. Both take two arguments, both required:

- **`resource`**: what the policy is about, as in CASL:
  - a string: Better Auth's resource name (the statement key), as is;
  - a symbol: named after its description;
  - a class: named after its static `modelName` if it has one, else its class name (`Post` → `"Post"`).
- **`config`**:
  - `statements`: role → allowed actions;
  - `actions`: every action of the resource. Required with enums, since types are erased at runtime; it defaults to the actions the statements grant;
  - `wildcard`: an action that expands to every action of the resource (e.g. `manage`). It is always an action of the policy.

Each action becomes an ability, typed: `@Can(PostPolicy, "delete")` doesn't compile unless `delete` is one of the actions.

```ts
import { Policy } from "@nestjs/authorization";
import { BetterAuthACPolicy, BetterAuthOrganizationACPolicy } from "nestjs-better-auth-adapter/authorization";
import type { BetterAuthUser } from "nestjs-better-auth-adapter";

enum Role { Admin = "admin", User = "user" }
enum Action { Manage = "manage", Create = "create", Update = "update" }

export class Post {
  id!: string;
  authorId!: string;
}

@Policy()
export class PostPolicy extends BetterAuthACPolicy<Role, Action>("post", {
  actions: Object.values(Action),
  wildcard: Action.Manage, // expands to every action when roles are built
  statements: {
    [Role.Admin]: [Action.Manage],
    [Role.User]: [Action.Create],
  },
}) {
  // Record-level rule on top of the role check.
  override update = async (user: BetterAuthUser | null, post?: Post) =>
    (!!user && post?.authorId === user.id) ||
    this.checkPermission(user, Action.Update);
}

// Without generics, roles and actions are inferred from the config.
@Policy()
export class ProjectPolicy extends BetterAuthOrganizationACPolicy(Project, {
  statements: { owner: ["create", "delete"], member: ["create"] },
}) {} // resource "Project"; abilities: create, delete
```

```ts
import { Can } from "@nestjs/authorization";
import { activeOrganization } from "nestjs-better-auth-adapter/authorization";

@Post()
@Can(PostPolicy, "create")
create() {}

@Post("projects")
@Can(ProjectPolicy, "create", activeOrganization) // the session's active organization
createProject() {}
```

Policies are providers: list them in a module. They work from `AuthorizationService` too, outside a request (`can(ProjectPolicy, 'create', user, organizationId)`).

### Custom mixins

A custom mixin is a function that calls `BetterAuthACPolicy()` (or `BetterAuthOrganizationACPolicy()`) with what your app always does: a naming rule for resources, fixed roles, a wildcard, default grants. Typed with the exported `ACPolicyResource`, `ACPolicyResourceClass` and `BetterAuthACPolicyConfig`, it stays as type-safe as the original.

**Classes as resources, named in lower case, with a wildcard and admins managing everything:**

```ts
import {
  type ACPolicyResourceClass,
  BetterAuthACPolicy,
  type BetterAuthACPolicyConfig,
} from "nestjs-better-auth-adapter/authorization";

export function AppPolicy<const TAction extends Action>(
  resource: ACPolicyResourceClass,
  config: Omit<BetterAuthACPolicyConfig<Role, TAction>, "wildcard">,
) {
  return BetterAuthACPolicy<Role, TAction | Action.Manage>(resource.name.toLowerCase(), {
    ...config,
    wildcard: Action.Manage,
    statements: { [Role.Admin]: [Action.Manage], ...config.statements },
  });
}

@Policy()
export class CommentPolicy extends AppPolicy(Comment, {
  actions: [Action.Create],
  statements: { [Role.User]: [Action.Create] },
}) {} // resource "comment"; abilities: create, manage
```

`AppPolicy("comment", …)` doesn't compile (resources are classes here), nor does a role outside `Role`, an action outside `Action`, or a `wildcard` (the mixin owns it).

**A mixin factory, for one naming strategy shared by every policy:** `resourceNameOf()` gives the default name of any resource (string, symbol or class); apply your rule on top.

```ts
import {
  type ACPolicyResource,
  BetterAuthACPolicy,
  type BetterAuthACPolicyConfig,
  resourceNameOf,
} from "nestjs-better-auth-adapter/authorization";

function createPolicyMixin<TRole extends string>(name: (resource: ACPolicyResource) => string) {
  return <const TAction extends string>(
    resource: ACPolicyResource,
    config: BetterAuthACPolicyConfig<TRole, TAction>,
  ) => BetterAuthACPolicy<TRole, TAction>(name(resource), config);
}

// BlogPost → "blog-post"
export const KebabPolicy = createPolicyMixin<Role>((resource) =>
  resourceNameOf(resource).replace(/([a-z])([A-Z])/g, "$1-$2").toLowerCase(),
);

@Policy()
export class BlogPostPolicy extends KebabPolicy(BlogPost, {
  statements: { [Role.Admin]: ["archive", "publish"] },
}) {} // abilities: archive, publish
```

The same pattern works for `BetterAuthOrganizationACPolicy()`. These examples are compiled in the package's type tests (`tests/types/ac-policy.test-d.ts`).

### Building `ac` and `roles` from the policies

`BetterAuthAccessControl` collects the policies at startup and builds what the plugins need, keeping Better Auth's own statements and roles so its endpoints keep working (`{ defaults: false }` leaves them out):

```ts
BetterAuthModule.forRootAsync({
  inject: [BetterAuthAccessControl],
  useFactory: (accessControl: BetterAuthAccessControl) => ({
    auth: betterAuth({
      plugins: [
        nestjs(),
        admin(accessControl.admin()),
        organization(accessControl.organization()),
      ],
    }),
  }),
});
```

Each resource belongs to one policy per scope; two policies defining the same one fail at startup. With `organization({ dynamicAccessControl })`, roles stored in the database are honored.

### Role and permission checks without a policy class

`BetterAuthPermissionPolicy` (from `BetterAuthAuthorizationModule`) exposes Better Auth's checks as abilities for `@Can()`:

```ts
@Module({ imports: [BetterAuthAuthorizationModule] })

@Can(BetterAuthPermissionPolicy, "hasRole", () => [["admin"]] as const)
@Can(BetterAuthPermissionPolicy, "userHasPermission", () => [{ project: ["create"] }] as const)
@Can(BetterAuthPermissionPolicy, "hasActiveOrganization", activeOrganization)
@Can(BetterAuthPermissionPolicy, "hasOrganizationRole", async (ctx) =>
  [...(await activeOrganization(ctx)), ["owner"]] as const)
@Can(BetterAuthPermissionPolicy, "memberHasPermission", async (ctx) =>
  [...(await activeOrganization(ctx)), { project: ["create"] }] as const)
```

Guests are denied, and Nest answers `401` for them; a signed-in user without the permission gets `403`.

## GraphQL and WebSockets

`AuthenticationModule`'s guard covers resolvers and gateways. The providers read the request (GraphQL), socket.io's handshake, or, on the `ws` adapter, the upgrade request `WsAuthenticator` keeps on the client.

- **GraphQL:** the providers read the request as `context.req`, and the session provider sends its refreshed cookies through the response, `context.res` (Express) or `context.reply` (Fastify). What each driver needs (all tested on Express and Fastify):

| Driver | `context` |
| --- | --- |
| `ApolloDriver`, `ApolloFederationDriver` (`@nestjs/apollo`), on Express | `({ req, res }) => ({ req, res })` |
| The same, on Fastify | `(req, reply) => ({ req, reply })`: Apollo passes Fastify's request and reply as two arguments |
| `YogaDriver`, `YogaFederationDriver` (`@graphql-yoga/nestjs`) | Nothing: Yoga's context is `{ req, res }` on Express, `{ req, reply }` on Fastify |

  Build Apollo's context per request: Nest refuses an object at startup. Without the response in it, requests still authenticate, but the cookies `getSession()` refreshes (sliding expiry, the cookie cache) never reach the browser.
- **Subscriptions over SSE** (Yoga's, on the GraphQL endpoint) are authenticated like queries, by the session cookie, a `Bearer` token or an OAuth access token on a subscription with `@OAuthScopes()`. A subscription refused before its first event has errors and no `data`, which Yoga answers with a 500, unless the error carries `extensions.http.status`. A GraphQL exception filter can give it Nest's status, a 401 or a 403. Refused queries then get it too, instead of a 200:

```ts
import { Catch, HttpException } from "@nestjs/common";
import type { GqlExceptionFilter } from "@nestjs/graphql";
import { GraphQLError } from "graphql";

@Catch(HttpException)
export class HttpStatusFilter implements GqlExceptionFilter {
  catch(exception: HttpException) {
    return new GraphQLError(exception.message, {
      originalError: exception,
      extensions: { http: { status: exception.getStatus() } },
    });
  }
}
```

- **Federation subgraphs:** Nest runs guards on a reference resolver (`@ResolveReference()`) only with `fieldResolverEnhancers: ["guards"]` in the `GraphQLModule` options. `@nestjs/authorization` fails at startup when `@Can()` is on one without it. With it, `@Authenticate()` and `@Can()` see the caller there as anywhere else, though a reference resolver gets no `args`.
- **WebSockets:** send the cookie or `Authorization: Bearer <token>` in the handshake, or a `jwt()` JWT as `auth: { token }` (socket.io). Install `@nestjs/websockets`.

Nest runs no guard on a gateway's `handleConnection()`, so authenticate the handshake with Nest's `WsAuthenticator`, as its docs show. It closes a connection nobody signed in on (1008, or socket.io's `disconnect()`), and the guard then authenticates every message again, so a session revoked mid-connection stops working:

```ts
import type { IncomingMessage } from "node:http";
import { WsAuthenticator } from "@nestjs/authentication";
import { type OnGatewayConnection, WebSocketGateway } from "@nestjs/websockets";
import type { WebSocket } from "ws";

// @nestjs/platform-ws: app.useWebSocketAdapter(new WsAdapter(app))
@WebSocketGateway({ path: "/ws" })
export class OrdersGateway implements OnGatewayConnection {
  constructor(private readonly wsAuthenticator: WsAuthenticator) {}

  async handleConnection(client: WebSocket, request: IncomingMessage) {
    await this.wsAuthenticator.authenticateConnection(client, request);
  }
}
```

With socket.io, `WsAuthenticator` reads the handshake itself: `authenticateConnection(client)`. Pass `{ required: false }` to keep guests connected. A handshake's cookie from an origin Better Auth doesn't trust counts as none, so a page on another site can't open a connection as your user.

## Options

`BetterAuthModule.forRoot(options)`, or what `forRootAsync()` resolves:

| Option | Default | |
| --- | --- | --- |
| `auth` | required | The `betterAuth({...})` instance, with the `nestjs()` plugin. |
| `routes` | `true` | Serve Better Auth's routes; `false` for an app that only authenticates ([above](#serving-better-auths-routes-from-one-service-only)). |
| `trustedOriginsCors` | `true` | CORS on Better Auth's routes for the origins it trusts. |
| `jwksCacheControl` | `oauthProvider()`'s metadata policy | The `Cache-Control` of `jwt()`'s JWKS, when Better Auth sends none; `false` for none ([above](#routes-cors-and-body-parsing)). |
| `bodyParser.json` / `.urlencoded` | enabled | Parser options, and `enabled: false`. |
| `bodyParser.rawBody` | `false` | Attach `req.rawBody`. |
| `middleware` | | Wraps Better Auth's handler. |
| `isGlobal` | `true` | Top-level option of `forRoot()` / `forRootAsync()`. |

`nestjs(options)`:

| Option | Default | |
| --- | --- | --- |
| `mfa` | `true` | Record verified second factors on the session (`session.mfaVerifiedAt`). |
| `events` | `true` | Publish Better Auth's flows as `AuthenticationEvents` ([above](#authentication-events)). |

## Example app

[`example/`](example) is a real-world API built on this package: Postgres through `@nestjs/drizzle`, sessions in Redis, organizations, policies, MFA step-up, API keys, JWTs, hooks, email handlers, GraphQL and WebSockets, with e2e tests on Express and Fastify. Its README maps every feature above to the file that uses it.

## Development

```bash
bun install
bun run check      # Biome
bun run typecheck
bun run test       # e2e suites on Express, then Fastify
bun run build
bun run test:dist  # boots an app from dist/, with no TypeScript transform
```

The example is a workspace of this repository; see [its README](example/README.md) to run it.

## Coming from `@thallesp/nestjs-better-auth`

Each of its module options has a counterpart. Those with another name or owner here fail at startup with the replacement, rather than being ignored:

| `@thallesp/nestjs-better-auth` | Here |
| --- | --- |
| `disableControllers: true` | `BetterAuthModule.forRoot({ auth, routes: false })` |
| `disableGlobalAuthGuard: true` | `AuthenticationModule.forRoot({ globalGuard: false })`: the guard is `@nestjs/authentication`'s |
| `disableTrustedOriginsCors: true` | `trustedOriginsCors: false` |
| `bodyParser` (`json`, `urlencoded`, `rawBody`) | `bodyParser`, the same shape |
| `disableBodyParser` / `enableRawBodyParser` (deprecated there) | `bodyParser.json.enabled` / `bodyParser.urlencoded.enabled` / `bodyParser.rawBody` |
| `middleware` | `middleware` |
| `isGlobal` | `isGlobal` |

Its guard and decorators (`@AllowAnonymous()`, `@OptionalAuth()`, `@Session()`) are `@nestjs/authentication`'s here (`@Public()`, `@Authenticate({ optional: true })`, `@CurrentUser()` / `@CurrentSession()`), with [credential providers](#credential-providers) you register.

## Credits

Parts of this package (serving Better Auth's routes, body parsing, CORS, hook discovery) come from [`@thallesp/nestjs-better-auth`](https://github.com/ThallesP/nestjs-better-auth) by Thalles Passos, MIT licensed. Use that library if you want its own guard and decorators; this one is built on Nest's.

## License

MIT
