import {
	index,
	jsonb,
	pgTable,
	text,
	timestamp,
	uuid,
} from "drizzle-orm/pg-core";
import { organization, user } from "./auth-schema.ts";

/**
 * The app's own tables. Better Auth's (`auth-schema.ts`) live in the same
 * database and are referenced here, but belong to Better Auth: change them
 * through its API (`BetterAuthService`), not through Drizzle.
 */

const createdAt = () =>
	timestamp("created_at", { withTimezone: true }).notNull().defaultNow();
const updatedAt = () =>
	timestamp("updated_at", { withTimezone: true })
		.notNull()
		.defaultNow()
		.$onUpdate(() => new Date());

export const articles = pgTable(
	"articles",
	{
		id: uuid("id").primaryKey().defaultRandom(),
		// Null once the author deleted their account: published articles stay, anonymized.
		authorId: text("author_id").references(() => user.id, {
			onDelete: "set null",
		}),
		title: text("title").notNull(),
		body: text("body").notNull(),
		status: text("status", { enum: ["draft", "published"] })
			.notNull()
			.default("draft"),
		publishedAt: timestamp("published_at", { withTimezone: true }),
		createdAt: createdAt(),
		updatedAt: updatedAt(),
	},
	(table) => [index("articles_author_id_idx").on(table.authorId)],
);

export const projects = pgTable(
	"projects",
	{
		id: uuid("id").primaryKey().defaultRandom(),
		organizationId: text("organization_id")
			.notNull()
			.references(() => organization.id, { onDelete: "cascade" }),
		name: text("name").notNull(),
		description: text("description"),
		createdBy: text("created_by")
			.notNull()
			.references(() => user.id, { onDelete: "cascade" }),
		createdAt: createdAt(),
		updatedAt: updatedAt(),
	},
	(table) => [index("projects_organization_id_idx").on(table.organizationId)],
);

export const organizationBilling = pgTable("organization_billing", {
	organizationId: text("organization_id")
		.primaryKey()
		.references(() => organization.id, { onDelete: "cascade" }),
	plan: text("plan", { enum: ["free", "pro", "enterprise"] })
		.notNull()
		.default("free"),
	status: text("status", { enum: ["active", "past_due", "canceled"] })
		.notNull()
		.default("active"),
	updatedAt: updatedAt(),
});

/** No foreign keys: the trail outlives the users and organizations it names. */
export const auditEvents = pgTable(
	"audit_events",
	{
		id: uuid("id").primaryKey().defaultRandom(),
		action: text("action").notNull(),
		actorId: text("actor_id"),
		organizationId: text("organization_id"),
		ipAddress: text("ip_address"),
		requestId: text("request_id"),
		metadata: jsonb("metadata")
			.$type<Record<string, unknown>>()
			.notNull()
			.default({}),
		createdAt: createdAt(),
	},
	(table) => [index("audit_events_created_at_idx").on(table.createdAt)],
);

export type ArticleRow = typeof articles.$inferSelect;
export type ProjectRow = typeof projects.$inferSelect;
export type OrganizationBillingRow = typeof organizationBilling.$inferSelect;
export type AuditEventRow = typeof auditEvents.$inferSelect;
