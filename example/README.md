# Example: a real-world NestJS API on Better Auth

A multi-tenant SaaS API (organizations, projects, articles, billing, an audit trail) that uses every feature of `nestjs-better-auth-adapter`, the way a production app would: Postgres through Nest's Drizzle module, Redis for Better Auth's sessions, migrations, validated config, SMTP mail, domain events, GraphQL, WebSockets, and e2e tests on Express **and** Fastify.

```text
Better Auth (engine)  ──  nestjs() plugin  ──  BetterAuthModule  ──  @nestjs/authentication + @nestjs/authorization
   /api/auth/*                hooks, MFA,          providers,             @CurrentUser(), @Authenticate(),
   users, sessions,           rehashing            handlers, hooks        @Can(), policies
   plugins, schema
```

## Run it

Requires Node 22.18+ (it runs `.ts` scripts with type stripping), Bun and Docker.

```bash
# from the repository root: install the workspace and build the package
bun install
bun run build

cd example
cp .env.example .env
bun run db:up        # Postgres on :5433, Redis on :6380, Mailpit on :1026 (UI: http://localhost:8026)
bun run db:migrate   # Better Auth's tables and the app's, from ./drizzle
bun run start:dev    # http://localhost:3000
```

| URL | |
| --- | --- |
| `http://localhost:3000/api/auth/*` | Better Auth's routes (sign-up, sign-in, two-factor, organizations…) |
| `http://localhost:3000/api/auth/reference` | Their OpenAPI reference (`openAPI()` plugin) |
| `http://localhost:3000/api/v1/*` | The app's REST API |
| `http://localhost:3000/graphql` | GraphQL |
| `ws://localhost:3000/realtime` | socket.io namespace |
| `http://localhost:8026` | Every email the app sent (Mailpit) |

`HTTP_ADAPTER=fastify bun run start:dev` runs the same app on Fastify.

A first session, with `curl`:

```bash
curl -c jar -H 'content-type: application/json' \
  -d '{"name":"Ana","email":"ana@example.com","password":"correct-horse-battery"}' \
  localhost:3000/api/auth/sign-up/email
curl -b jar localhost:3000/api/v1/me
# Open the verification link from Mailpit, then:
curl -b jar -H 'content-type: application/json' -d '{"title":"Hello","body":"World"}' \
  localhost:3000/api/v1/articles
```

## Every feature, and where it is

### Wiring

| Feature | Where |
| --- | --- |
| `nestjs()` Better Auth plugin (`mfa: true`) | [`src/auth/create-auth.ts`](src/auth/create-auth.ts) |
| One `createAuth()` factory for the CLI and for Nest | [`create-auth.ts`](src/auth/create-auth.ts), [`auth.ts`](src/auth/auth.ts) (CLI), [`auth.config.ts`](src/auth/auth.config.ts) (Nest) |
| `BetterAuthModule.forRootAsync({ useClass })` + `BetterAuthOptionsFactory` | [`src/auth/auth.module.ts`](src/auth/auth.module.ts), [`auth.config.ts`](src/auth/auth.config.ts) |
| Credential providers extending the base classes, registered in their order, with `realm` and `headers` (matching `apiKey({ apiKeyHeaders })`) | [`src/auth/providers/`](src/auth/providers), [`auth.module.ts`](src/auth/auth.module.ts) |
| `DrizzleModule.forRootAsync()` (`@nestjs/drizzle`), `@InjectDrizzle()`: one pool for Better Auth and the app | [`src/app.module.ts`](src/app.module.ts), [`create-database.ts`](src/database/create-database.ts), [`auth.config.ts`](src/auth/auth.config.ts) |
| Redis as a global custom provider (`RedisModule`, `@InjectRedis()`), checked by `/health` | [`src/redis/redis.module.ts`](src/redis/redis.module.ts), [`meta.controller.ts`](src/meta/meta.controller.ts) |
| Better Auth's `secondaryStorage` on Redis (`@better-auth/redis-storage`): sessions, rate limits, the API key cache; a short `cookieCache` on top | [`create-auth.ts`](src/auth/create-auth.ts), tested in [`authentication.e2e-spec.ts`](test/authentication.e2e-spec.ts) |
| `bodyParser` (`json.limit`, `urlencoded`, `rawBody`) | [`auth.config.ts`](src/auth/auth.config.ts), used by the [billing webhook](src/billing/billing.controller.ts) |
| `middleware` (request context for Better Auth's routes) | [`auth.config.ts`](src/auth/auth.config.ts), [`src/common/request-context.ts`](src/common/request-context.ts) |
| `trustedOrigins` CORS | [`create-auth.ts`](src/auth/create-auth.ts), tested in [`authentication.e2e-spec.ts`](test/authentication.e2e-spec.ts) |
| Routes outside the global prefix (`/api/auth` vs `/api/v1`) | [`src/app.setup.ts`](src/app.setup.ts) |
| `bodyParser: false` in `NestFactory.create()` | [`src/main.ts`](src/main.ts) |
| Typing `@CurrentUser()`/`@CurrentSession()` (`BetterAuthAuthenticationTypes`) | [`src/auth/auth.types.ts`](src/auth/auth.types.ts) |
| `BetterAuthService<Auth>`: the typed instance, in hooks and providers | [`sensitive-routes.hooks.ts`](src/auth/hooks/sensitive-routes.hooks.ts), [`meta.controller.ts`](src/meta/meta.controller.ts) |
| Better Auth's routes as they are: profile, sessions, two-factor, API keys, `admin()` and `organization()` under `/api/auth`, with no controller of the app in front | used by the clients, and by the e2e suites |
| `hasPlugin()` / `findPlugin()` | [`src/meta/meta.controller.ts`](src/meta/meta.controller.ts) |

### Authentication

| Feature | Where |
| --- | --- |
| `BetterAuthSessionProvider`: cookie and `bearer()` token | everywhere; [`account.controller.ts`](src/account/account.controller.ts) restricts routes to it |
| `BetterAuthJwtProvider` (`jwt()`), `@CurrentSession()` = claims | [`src/integrations/integrations.controller.ts`](src/integrations/integrations.controller.ts) (`/internal`) |
| `BetterAuthApiKeyProvider` (`apiKey()`), via `ApiKeyProvider` | [`integrations.controller.ts`](src/integrations/integrations.controller.ts) (`/integrations`), keys created in [`account.controller.ts`](src/account/account.controller.ts) |
| `@Public()` | [`src/meta/meta.controller.ts`](src/meta/meta.controller.ts), [billing webhook](src/billing/billing.controller.ts) |
| `@Authenticate({ optional: true })` | [`articles.controller.ts`](src/articles/articles.controller.ts), GraphQL `viewer` |
| `@Authenticate({ verifiedEmail: true })` | creating articles; on Better Auth's routes (invitations, API keys), [`SensitiveRoutesHooks`](src/auth/hooks/sensitive-routes.hooks.ts) asks the same |
| `@Authenticate({ mfa: true })` (step-up) | deleting projects, plan changes; on Better Auth's routes (bans, deleting organizations, creating API keys, revoking other sessions), [`SensitiveRoutesHooks`](src/auth/hooks/sensitive-routes.hooks.ts) asks the same |
| `@CurrentUser('locale')` (an additional field) | [`account.controller.ts`](src/account/account.controller.ts) |
| `AuthenticationContext` in a service | [`src/projects/projects.service.ts`](src/projects/projects.service.ts), [`billing.controller.ts`](src/billing/billing.controller.ts) |
| `AuthenticationEvents` (Better Auth's sign-ins, sign-outs, second factors, password resets, verified addresses, published by the `nestjs()` plugin) in the audit trail, as `auth.<type>` | [`src/audit/audit.service.ts`](src/audit/audit.service.ts), tested in [`authentication.e2e-spec.ts`](test/authentication.e2e-spec.ts) |
| GraphQL and socket.io | [`projects.resolver.ts`](src/projects/projects.resolver.ts), [`projects.gateway.ts`](src/projects/projects.gateway.ts) |

### Nest handlers and `PasswordHasher`

| Feature | Where |
| --- | --- |
| `BetterAuthPasswordResetHandler`, `BetterAuthEmailVerificationHandler`, `BetterAuthMagicLinkHandler`, registered in `AuthenticationRegistry`; the frontend pages as the features' `url` | [`password-reset.mailer.ts`](src/auth/handlers/password-reset.mailer.ts), [`email-verification.mailer.ts`](src/auth/handlers/email-verification.mailer.ts), [`magic-link.mailer.ts`](src/auth/handlers/magic-link.mailer.ts), [`auth.module.ts`](src/auth/auth.module.ts) |
| `fromNestHandler` | `magicLink({ sendMagicLink: fromNestHandler })` in [`create-auth.ts`](src/auth/create-auth.ts) |
| `BetterAuthOidcAccountResolver` registered as `oidc`, plugged into Better Auth's `user.validateUserInfo` (the app's own rule on top of Better Auth's `accountLinking`) | [`account-linking.resolver.ts`](src/auth/handlers/account-linking.resolver.ts), [`auth.module.ts`](src/auth/auth.module.ts) |
| `betterAuthPassword(hasher)` (Nest) / `nestPasswordHasher()` (CLI) | [`create-auth.ts`](src/auth/create-auth.ts); cost set in [`auth.module.ts`](src/auth/auth.module.ts) |

### Hooks

| Feature | Where |
| --- | --- |
| `@Hook()`, `@BeforeHook(path)`, `@AfterHook(path)`, `@AfterHook()` (every route) | [`src/auth/hooks/auth-request.hooks.ts`](src/auth/hooks/auth-request.hooks.ts) |
| `@BeforeHook()` without a path, with `BetterAuthService.authenticate(ctx)`: the app's step-up rules on Better Auth's sensitive routes, by the same `mfa: 'verified'` as Nest's guard | [`src/auth/hooks/sensitive-routes.hooks.ts`](src/auth/hooks/sensitive-routes.hooks.ts) |
| `@DatabaseHook()` with all six decorators, on `user`, `session`, `account` | [`user-database.hooks.ts`](src/auth/hooks/user-database.hooks.ts), [`session-database.hooks.ts`](src/auth/hooks/session-database.hooks.ts) |

### Authorization

| Feature | Where |
| --- | --- |
| `BetterAuthACPolicy` with TypeScript enums, `wildcard`, record-level override | [`src/articles/article.policy.ts`](src/articles/article.policy.ts) |
| `BetterAuthOrganizationACPolicy` + `activeOrganization`, a `before()` hook, an injected dependency | [`src/projects/project.policy.ts`](src/projects/project.policy.ts) |
| `BetterAuthOrganizationACPolicy` with inferred roles/actions and a custom role | [`src/billing/billing.policy.ts`](src/billing/billing.policy.ts) |
| A custom mixin (`resourceNameOf`, `ACPolicyResourceClass`, `BetterAuthACPolicyConfig`) | [`src/authorization/platform-policy.ts`](src/authorization/platform-policy.ts), used by [`audit-log.policy.ts`](src/audit/audit-log.policy.ts) |
| `BetterAuthAccessControl` → `admin()`/`organization()` `ac` and `roles`, which Better Auth's own admin and organization routes check (bans, user listing, invitations, deleting an organization) | [`auth.config.ts`](src/auth/auth.config.ts) → [`create-auth.ts`](src/auth/create-auth.ts), tested in [`platform.e2e-spec.ts`](test/platform.e2e-spec.ts), [`organizations.e2e-spec.ts`](test/organizations.e2e-spec.ts) |
| `organization({ dynamicAccessControl })` roles honored by policies | tested in [`organizations.e2e-spec.ts`](test/organizations.e2e-spec.ts) |
| `BetterAuthOrganizationACPolicy` on an entity class, roles only (owners and admins read) | [`src/audit/organization-audit-log.policy.ts`](src/audit/organization-audit-log.policy.ts), used by [`organization-audit.controller.ts`](src/audit/organization-audit.controller.ts) (the organization's audit trail) |
| `@Can()` resolvers: route param, query, GraphQL arg, WebSocket payload | [`src/common/can-args.ts`](src/common/can-args.ts) |
| `AuthorizationService.authorize()` / `can()` on records | [`src/articles/articles.service.ts`](src/articles/articles.service.ts) |

## Layout

```text
src/
├── main.ts, app.module.ts, app.setup.ts   bootstrap, shared with the e2e suites
├── config/          validated environment (zod), injected as ENV
├── database/        Drizzle: schema (auth-schema.ts is generated), pool options, migrations
├── redis/           RedisModule: the ioredis client, Better Auth's secondary storage
├── auth/            createAuth(), BetterAuthModule wiring, handlers, hooks, types
├── authorization/   roles and the app's policy mixin
├── common/          request context, @Can() resolvers
├── mail/            Mailer (SMTP), templates, lifecycle emails
├── audit/           audit trail (events → table), AuditLogPolicy
├── account/  articles/  projects/  billing/  integrations/  meta/
drizzle/             SQL migrations (drizzle-kit)
test/                e2e suites against Postgres, on Express and Fastify
```

## Database, Redis and migrations

Better Auth's tables and the app's share one Drizzle schema and one migration history:

1. `src/database/schema/auth-schema.ts` is generated by Better Auth's CLI from the config (`bun run auth:generate`), plugins and the `nestjs()` plugin's `session.mfaVerifiedAt` column included. Regenerate it after adding a plugin or a field.
2. `src/database/schema/app-schema.ts` holds the app's tables, which reference Better Auth's.
3. `bun run db:generate` writes the SQL migration; `bun run db:migrate` applies it.

Postgres is registered with Nest's [`@nestjs/drizzle`](https://docs.nestjs.com/data/drizzle): `DrizzleModule.forRootAsync()` in `AppModule` builds the pool from the validated `ENV`, `@InjectDrizzle()` injects it, and the module closes it on shutdown. The Better Auth CLI and the migration script build the same database outside Nest, with `createDatabase()`.

Better Auth keeps in Redis what every request, or every instance, touches:

| In Redis (`secondaryStorage`) | In Postgres |
| --- | --- |
| Sessions: read on each authenticated request; a sign-out, a revoked session or a ban reaches every instance at the next one | Users, accounts, organizations, members, two-factor secrets |
| Rate limits, counted atomically for every instance (so no `rate_limit` table: [`0001_redis_secondary_storage.sql`](drizzle/0001_redis_secondary_storage.sql) drops it) | API keys, the source of truth; Redis caches them in front (`fallbackToDatabase`) |
| Verification tokens, single-use | The app's tables |

- **Redis must persist.** Sessions live only there, so `docker-compose.yml` turns its append-only file on. `session.storeSessionInDatabase: true` would write them to Postgres as well, and `oauthProvider()` requires it.
- **The cookie cache lasts a minute.** It skips even Redis while it is fresh, and it is how long a revoked session or a ban can lag behind.
- **Redis is checked at boot.** `RedisModule` connects before the app starts, so an unreachable Redis fails the boot, not the first sign-in.

## Tests

```bash
bun run db:up
bun run test          # every suite on Express, then on Fastify
bun run test:fastify  # one adapter
```

The suites boot the real `AppModule` against a `acme_test` database and Redis database `1` (both reset once per run), with one override: email goes to an in-memory outbox, from which tests open verification, reset and magic links like a browser would.

## Things worth knowing

Lessons this example ran into, each handled in the code:

- **Don't wrap Better Auth's routes in controllers.** Its admin and organization routes already check the caller against the `ac` built from your policies. Add the app's own rules to them with a hook, as [`SensitiveRoutesHooks`](src/auth/hooks/sensitive-routes.hooks.ts) does, and keep controllers for the app's own data.
- **A two-factor verification replaces the session.** Clients must pick up the new token (`set-auth-token` with `bearer()`, or the new cookie).
- **Don't refuse a user deletion in `@BeforeDelete('user')`.** Better Auth deletes the user's sessions and accounts (password included) before that hook runs. Refuse in a request hook (`@BeforeHook('/delete-user')`), as [`auth-request.hooks.ts`](src/auth/hooks/auth-request.hooks.ts) does.
- **In a `@BeforeHook`, read the session through `betterAuth.api.getSession({ headers })`.** `getSessionFromCtx(ctx)` may run before `bearer()` turned the token into a cookie.
- **`@Authenticate({ mfa: true })` runs before `@Can()`.** A user without a second factor gets 401 `mfa_required` even where their role would get 403.
- **`session.mfaVerifiedAt` isn't in Better Auth's `$Infer`.** [`auth.types.ts`](src/auth/auth.types.ts) adds it from `BetterAuthSession`.
- **Every route needs `@Can()`, `@Can.Anyone()` or `@Public()`** once `AuthorizationModule` is imported: authenticated-only controllers use `@Can.Anyone()`.
