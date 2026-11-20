import { SetMetadata } from "@nestjs/common";
import type { CustomDecorator } from "@nestjs/common";
import {
	AFTER_DATABASE_HOOK_KEY,
	AFTER_HOOK_KEY,
	BEFORE_DATABASE_HOOK_KEY,
	BEFORE_HOOK_KEY,
	DATABASE_HOOK_KEY,
	HOOK_KEY,
} from "../constants.ts";
import type {
	DatabaseHookModel,
	DatabaseHookOperation,
} from "../interfaces/hooks.interface.ts";

/**
 * Marks a provider whose methods are Better Auth request hooks
 * (`@BeforeHook()`, `@AfterHook()`). They run inside Better Auth, through
 * the `nestjs()` plugin, and can inject anything the provider's module can.
 */
export const Hook = (): ClassDecorator => SetMetadata(HOOK_KEY, true);

/**
 * Runs the method before Better Auth handles `path` (every route when
 * omitted). It receives Better Auth's hook context; what it returns is what
 * a Better Auth `before` hook returns.
 */
export const BeforeHook = (path?: `/${string}`): CustomDecorator<symbol> =>
	SetMetadata(BEFORE_HOOK_KEY, path);

/**
 * Runs the method after Better Auth handled `path` (every route when
 * omitted). A value it returns replaces the response, as with a Better Auth
 * `after` hook.
 */
export const AfterHook = (path?: `/${string}`): CustomDecorator<symbol> =>
	SetMetadata(AFTER_HOOK_KEY, path);

/** Marks a provider whose methods are Better Auth database hooks (`@BeforeCreate()`…). */
export const DatabaseHook = (): ClassDecorator =>
	SetMetadata(DATABASE_HOOK_KEY, true);

const databaseHook =
	(key: symbol, operation: DatabaseHookOperation) =>
	(model: DatabaseHookModel): CustomDecorator<symbol> =>
		SetMetadata(key, { model, operation });

/** Runs before a record of `model` is created. Return `false` to cancel, or `{ data }` to change it. */
export const BeforeCreate = databaseHook(BEFORE_DATABASE_HOOK_KEY, "create");
/** Runs after a record of `model` is created. */
export const AfterCreate = databaseHook(AFTER_DATABASE_HOOK_KEY, "create");
/** Runs before a record of `model` is updated. Return `false` to cancel, or `{ data }` to change it. */
export const BeforeUpdate = databaseHook(BEFORE_DATABASE_HOOK_KEY, "update");
/** Runs after a record of `model` is updated. */
export const AfterUpdate = databaseHook(AFTER_DATABASE_HOOK_KEY, "update");
/** Runs before a record of `model` is deleted. Return `false` to cancel. */
export const BeforeDelete = databaseHook(BEFORE_DATABASE_HOOK_KEY, "delete");
/** Runs after a record of `model` is deleted. */
export const AfterDelete = databaseHook(AFTER_DATABASE_HOOK_KEY, "delete");
