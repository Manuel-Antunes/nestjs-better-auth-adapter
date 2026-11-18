# nestjs-better-auth-adapter

[Better Auth](https://better-auth.com) for [NestJS](https://nestjs.com), through Nest's own security packages: [`@nestjs/authentication`](https://docs.nestjs.com/security/authentication) and [`@nestjs/authorization`](https://docs.nestjs.com/security/authorization).

Better Auth stays the engine: it serves its routes (`/api/auth/*`), stores users and sessions, and runs its plugins and client SDK as usual. This package plugs it into the ports Nest defines:

| Nest port | Better Auth behind it |
| --- | --- |
| `AuthenticationRegistry` credential providers | The session (cookie, and Bearer with `bearer()`), JWTs from `jwt()`, keys from `apiKey()` |
| `@CurrentUser()`, `@CurrentSession()`, `AuthenticationContext`, `@Authenticate({ verifiedEmail, mfa, optional, providers })` | Better Auth's user and session, plugin and additional fields included |
| `PasswordResetHandler`, `EmailVerificationHandler`, `MagicLinkHandler` | Deliver Better Auth's links |
| `OidcAccountResolver` | Decides which user a social/OAuth identity links to |
| `PasswordHasher` | Hashes Better Auth's passwords |
| `@Policy()` / `@Can()` | Better Auth's access control (`admin()` and `organization()` plugins) |

Every integration past authentication is optional: without the matching Nest provider, Better Auth keeps what its own config says.

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Authentication](#authentication)
- [Second factor (MFA)](#second-factor-mfa)
- [Module configuration](#module-configuration)
- [Hooks](#hooks)
- [Nest handlers and `PasswordHasher`](#nest-handlers-and-passwordhasher)
- [Authorization](#authorization)
- [GraphQL and WebSockets](#graphql-and-websockets)
- [Options](#options)
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

**3. Turn Nest's body parser off.** Better Auth reads the raw body of its own routes; this module adds the parsers back for every other route.

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

`BetterAuthModule` registers these in `AuthenticationRegistry`. The first that returns a user wins.

| Provider | Credentials | `@CurrentSession()` | Registered when |
| --- | --- | --- | --- |
| `BetterAuthSessionProvider` (order 0) | Session cookie; `Authorization: Bearer <session token>` with `bearer()` | Better Auth's session | Always |
| `BetterAuthJwtProvider` (order 1) | `Authorization: Bearer <jwt>` from `jwt()` (`/token`, `set-auth-jwt`), checked against its JWKS | The JWT claims | `jwt()` is configured |
| `BetterAuthApiKeyProvider` (order 2) | `x-api-key`, or the headers in `providers.apiKey.headers` | `{ method: 'api-key', keyId, expiresAt? }` | `apiKey()` is configured |

- Bearer tokens that don't look like a JWT (two dots) are left to the session provider, so JWTs and session tokens coexist.
- The API key provider extends Nest's `ApiKeyProvider` but delegates the whole check to Better Auth's `verifyApiKey`: its rate limits, remaining counts and permissions apply. Only keys owned by a user sign in. Leave `enableSessionForAPIKeys` off, or Better Auth turns the key into a session first. A refused key always answers a generic `Invalid API key`; the reason is logged at debug level.
- A key or a JWT never satisfies `@Authenticate({ mfa: true })`.
- The `apiKey()` plugin doesn't expose its options: if you set its `apiKeyHeaders`, set the same in `providers.apiKey.headers`.

Change the order, the realm of the API key challenge, or leave a provider out:

```ts
BetterAuthModule.forRoot({
  auth,
  providers: {
    session: { order: 0 },
    jwt: false,
    apiKey: { order: 1, realm: "partners", headers: "x-partner-key" },
  },
});
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

### Routes, CORS and body parsing

- Better Auth's routes are served under its `basePath` (`/api/auth` by default), outside any global prefix. `routes: false` leaves them out, to mount `toNodeHandler(auth)` yourself.
- When Better Auth's `trustedOrigins` is a string array, CORS is enabled for those origins with credentials. `trustedOriginsCors: false` leaves CORS to you. A function `trustedOrigins` needs `trustedOriginsCors: false`.
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

- `middleware` wraps Better Auth's handler, e.g. for MikroORM's `RequestContext`:

```ts
BetterAuthModule.forRoot({
  auth,
  middleware: (req, res, next) => RequestContext.create(orm.em, next),
});
```

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

All optional. Provide the Nest class and the module plugs it in; leave it out and Better Auth uses its own config.

### Email handlers

A provider extending `PasswordResetHandler`, `EmailVerificationHandler` or `MagicLinkHandler` delivers Better Auth's links. Better Auth still creates and checks the tokens, so `send()` is the only method it calls, and none of `AuthenticationModule`'s `passwordReset`/`emailVerification`/`magicLink` options or stores are needed.

```ts
@Injectable()
export class ResetMailer extends PasswordResetHandler {
  constructor(private readonly mailer: Mailer) {
    super();
  }

  send({ email, url, expiresAt }: PasswordResetLink) {
    return this.mailer.send(email, "Reset your password", url);
  }

  // Part of Nest's contract, unused here: Better Auth owns these steps.
  findUser() {
    return null;
  }
  updatePassword() {}
}
```

| Handler | Replaces | Requires in the Better Auth config |
| --- | --- | --- |
| `PasswordResetHandler` | `emailAndPassword.sendResetPassword` | `emailAndPassword: { enabled: true }` |
| `EmailVerificationHandler` | `emailVerification.sendVerificationEmail` | `emailVerification: {}` |
| `MagicLinkHandler` | `magicLink({ sendMagicLink })` | `magicLink({ sendMagicLink: fromNestHandler })` |

`fromNestHandler` (from `nestjs-better-auth-adapter/plugin`) fills a callback Better Auth's types require; startup fails if no handler replaces it. A handler replaces a callback the config defines, and says so in the logs.

### `OidcAccountResolver`

A provider extending `OidcAccountResolver` decides, before Better Auth stores a social or OAuth account, which user it belongs to. Return that user (`{ id }`), or `null` to refuse the link: Better Auth answers `403` and creates neither the account nor, for a new identity, the user.

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

`AuthenticationModule`'s guard covers resolvers and gateways, and the session provider reads the request (GraphQL) or the handshake (socket.io) headers.

- GraphQL: build the context per request, `context: ({ req, res }) => ({ req, res })`; Nest refuses an object at startup.
- WebSockets: send the cookie or `Authorization: Bearer <token>` in the handshake. Install `@nestjs/websockets`.

## Options

`BetterAuthModule.forRoot(options)`, or what `forRootAsync()` resolves:

| Option | Default | |
| --- | --- | --- |
| `auth` | required | The `betterAuth({...})` instance, with the `nestjs()` plugin. |
| `providers.session` | `{ order: 0 }` | `false` leaves the provider out. |
| `providers.jwt` | `{ order: 1 }` | Registered only with `jwt()`. |
| `providers.apiKey` | `{ order: 2, realm: 'api', headers: 'x-api-key' }` | Registered only with `apiKey()`. |
| `routes` | `true` | Serve Better Auth's routes under its `basePath`. |
| `trustedOriginsCors` | `true` | CORS for Better Auth's `trustedOrigins`. |
| `bodyParser.json` / `.urlencoded` | enabled | Parser options, and `enabled: false`. |
| `bodyParser.rawBody` | `false` | Attach `req.rawBody`. |
| `middleware` | | Wraps Better Auth's handler. |
| `isGlobal` | `true` | Top-level option of `forRoot()` / `forRootAsync()`. |

`nestjs(options)`:

| Option | Default | |
| --- | --- | --- |
| `mfa` | `true` | Record verified second factors on the session (`session.mfaVerifiedAt`). |

## Development

```bash
bun install
bun run check      # Biome
bun run typecheck
bun run test       # e2e suites on Express, then Fastify
bun run build
bun run test:dist  # boots an app from dist/, with no TypeScript transform
```

## Credits

Parts of this package (serving Better Auth's routes, body parsing, CORS, hook discovery) come from [`@thallesp/nestjs-better-auth`](https://github.com/ThallesP/nestjs-better-auth) by Thalles Passos, MIT licensed. Use that library if you want its own guard and decorators; this one is built on Nest's.

## License

MIT
