import { apiKey } from "@better-auth/api-key";
import { redisStorage } from "@better-auth/redis-storage";
import type { PasswordHasher } from "@nestjs/authentication";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import {
  admin,
  bearer,
  jwt,
  magicLink,
  openAPI,
  organization,
  twoFactor,
} from "better-auth/plugins";
import type { AccessControl } from "better-auth/plugins/access";
import {
  defaultAc as defaultOrganizationAc,
  defaultRoles as defaultOrganizationRoles,
} from "better-auth/plugins/organization/access";
import type { Redis } from "ioredis";
import type {
  BetterAuthAccessControl,
  BetterAuthAccessControlOptions,
} from "nestjs-better-auth-adapter";
import {
  betterAuthPassword,
  fromNestHandler,
  nestjs,
  nestPasswordHasher,
} from "nestjs-better-auth-adapter/plugin";
import { OrganizationRole } from "../authorization/enums/organization-role.enum.ts";
import { PlatformRole } from "../authorization/enums/platform-role.enum.ts";
import type { Env } from "../config/env.ts";
import type { Database } from "../database/create-database.ts";
import * as schema from "../database/schema/index.ts";

/**
 * The headers API keys are read from. The `apiKey()` plugin doesn't expose
 * its options, so `ApiKeyAuth` passes the same list to its base class (see
 * `providers/api-key.auth.ts`).
 */
export const API_KEY_HEADERS = ["x-api-key"];

/** What differs between the Better Auth CLI, the migration script and the app. */
export interface CreateAuthOptions {
  env: Env;
  db: Database;
  /**
   * Better Auth's secondary storage, shared by every instance of the app.
   * The app injects its connection (`RedisModule`); the CLI passes one that
   * never connects, since it only reads the schema.
   */
  redis: Redis;
  /**
   * Nest's `PasswordHasher`, injected by the app. The CLI and the migration
   * script never hash a password, so they leave it out and get the
   * `nestPasswordHasher()` placeholder, which `BetterAuthModule` would bind.
   */
  hasher?: PasswordHasher;
  /**
   * The `ac` and `roles` built from the app's policies by
   * `BetterAuthAccessControl`. Left out by the CLI: they change no table.
   */
  accessControl?: Pick<BetterAuthAccessControl, "admin" | "organization">;
  /** Wraps Better Auth's logs, so they go through Nest's `Logger`. */
  logger?: BetterAuthOptions["logger"];
}

/**
 * The whole Better Auth config, in one place. Called by `auth.ts` (for the
 * Better Auth CLI, with environment variables) and by `AuthConfig` (for Nest,
 * with injected services). Mind what this file imports: the CLI loads it
 * without Nest, so keep Nest providers and decorators out of it.
 */
export function createAuth({
  env,
  db,
  redis,
  hasher,
  accessControl,
  logger,
}: CreateAuthOptions) {
  const production = env.NODE_ENV === "production";
  const socialProviders: BetterAuthOptions["socialProviders"] = {};
  if (env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET) {
    socialProviders.github = {
      clientId: env.GITHUB_CLIENT_ID,
      clientSecret: env.GITHUB_CLIENT_SECRET,
    };
  }
  if (env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET) {
    socialProviders.google = {
      clientId: env.GOOGLE_CLIENT_ID,
      clientSecret: env.GOOGLE_CLIENT_SECRET,
    };
  }

  const adminAccessControl = accessControl?.admin();
  // Without the app's policies (the CLI), Better Auth's defaults: the schema is the same.
  const organizationAccessControl: BetterAuthAccessControlOptions =
    accessControl?.organization() ?? {
      ac: defaultOrganizationAc as AccessControl,
      roles: defaultOrganizationRoles,
    };

  return betterAuth({
    appName: env.APP_NAME,
    baseURL: env.BETTER_AUTH_URL,
    secret: env.BETTER_AUTH_SECRET,
    // A string array: BetterAuthModule enables CORS for these origins.
    trustedOrigins: env.TRUSTED_ORIGINS,
    // Better Auth's tables, through its Drizzle adapter, on the app's pool.
    // Their schema is generated into auth-schema.ts: `bun run auth:generate`.
    database: drizzleAdapter(db, { provider: "pg", schema }),
    // Redis, for what every request or every instance touches: sessions
    // (read on each authenticated request), rate limits, verification
    // tokens, and the API key cache below. Users, accounts and
    // organizations stay in Postgres.
    secondaryStorage: redisStorage({ client: redis }),
    logger: logger ?? { disabled: env.NODE_ENV === "test" },
    telemetry: { enabled: false },

    emailAndPassword: {
      enabled: true,
      minPasswordLength: 12,
      maxPasswordLength: 128,
      revokeSessionsOnPasswordReset: true,
      // scrypt through Nest's PasswordHasher. Hashes made before the switch
      // keep verifying, and are upgraded at the next sign-in.
      password: hasher ? betterAuthPassword(hasher) : nestPasswordHasher(),
      // sendResetPassword: delivered by the passwordReset handler in AuthenticationRegistry (PasswordResetMailer).
    },
    emailVerification: {
      sendOnSignUp: true,
      autoSignInAfterVerification: true,
      // sendVerificationEmail: delivered by the emailVerification handler in AuthenticationRegistry (EmailVerificationMailer).
    },
    socialProviders,
    account: {
      // Better Auth links a provider to an existing account by email only
      // when the provider verified the address and so did the account's
      // owner: someone who registered the address first, unverified,
      // can't keep access (account pre-hijacking). AccountLinkingResolver
      // adds the app's own rules on top, through user.validateUserInfo.
      accountLinking: { enabled: true, requireLocalEmailVerified: true },
    },

    user: {
      additionalFields: {
        locale: {
          type: "string",
          required: false,
          defaultValue: "en",
          input: true,
        },
      },
      deleteUser: { enabled: true },
    },
    session: {
      expiresIn: 60 * 60 * 24 * 30,
      updateAge: 60 * 60 * 24,
      // Sessions live in Redis only: a sign-out, a revoked session or a ban
      // reaches every instance at the next request. Redis must persist
      // (docker-compose.yml turns its AOF on). `storeSessionInDatabase: true`
      // would write them to Postgres as well, as oauthProvider() requires.
      //
      // On top, a short cookie cache skips even Redis for a minute. It is
      // how long a revoked session or a ban can lag behind. The nestjs()
      // plugin refreshes the cached cookie when a session passes MFA.
      cookieCache: { enabled: true, maxAge: 60 },
    },

    rateLimit: {
      enabled: production,
      // Counted in Redis, atomically: shared by every instance of the app.
      storage: "secondary-storage",
      customRules: {
        "/sign-in/*": { window: 60, max: 5 },
        "/two-factor/*": { window: 60, max: 5 },
        "/forget-password": { window: 60 * 15, max: 3 },
      },
    },
    advanced: {
      cookiePrefix: "acme",
      ipAddress: { ipAddressHeaders: ["x-forwarded-for"] },
    },

    plugins: [
      // Session tokens as `Authorization: Bearer`, for mobile apps and socket.io clients.
      bearer(),
      // Short-lived JWTs for other services, checked against /api/auth/jwks.
      jwt({
        jwt: {
          issuer: env.BETTER_AUTH_URL,
          audience: env.BETTER_AUTH_URL,
          expirationTime: "15m",
          definePayload: ({ user }) => ({
            email: user.email,
            role: (user as { role?: string }).role,
          }),
        },
      }),
      apiKey({
        apiKeyHeaders: API_KEY_HEADERS,
        defaultPrefix: "acme_",
        requireName: true,
        enableMetadata: true,
        keyExpiration: { maxExpiresIn: 365 },
        rateLimit: { enabled: true, timeWindow: 60_000, maxRequests: 120 },
        // Keys are verified on every request: Redis caches them in front of
        // Postgres, which stays the source of truth (listing, revocation).
        storage: "secondary-storage",
        fallbackToDatabase: true,
        // enableSessionForAPIKeys stays off: BetterAuthApiKeyProvider verifies keys itself.
      }),
      twoFactor({ issuer: env.APP_NAME }),
      // Delivered by the magicLink handler in AuthenticationRegistry (MagicLinkMailer); startup
      // fails if no handler replaces this placeholder.
      magicLink({
        sendMagicLink: fromNestHandler,
        expiresIn: 60 * 5,
        disableSignUp: true,
      }),
      admin({
        ...adminAccessControl,
        defaultRole: PlatformRole.User,
        adminRoles: [PlatformRole.Admin],
      }),
      organization({
        ...organizationAccessControl,
        creatorRole: OrganizationRole.Owner,
        // Roles created at runtime (`/organization/create-role`) are honored by the policies.
        dynamicAccessControl: { enabled: true },
        // The invitation email is sent by AuthRequestHooks (@AfterHook).
      }),
      // Better Auth's endpoints, documented at /api/auth/reference.
      openAPI(),
      // Connects Better Auth to BetterAuthModule: @Hook()/@DatabaseHook()
      // providers, the second factor on the session, password rehashing.
      nestjs({ mfa: true }),
    ],
  });
}

/** The instance's type, plugins and additional fields included. */
export type Auth = ReturnType<typeof createAuth>;
