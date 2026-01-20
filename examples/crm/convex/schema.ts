import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

export default defineSchema({
  users: defineTable({
    name: v.string(),
    email: v.string(),
    avatar: v.optional(v.string()),
  }).index("by_email", ["email"]),

  orgs: defineTable({
    name: v.string(),
    slug: v.string(),
    plan: v.string(),
  }).index("by_slug", ["slug"]),

  contacts: defineTable({
    orgId: v.string(),
    name: v.string(),
    email: v.string(),
  }).index("by_org", ["orgId"]),

  deals: defineTable({
    orgId: v.string(),
    title: v.string(),
    value: v.number(),
    stage: v.string(),
  }).index("by_org", ["orgId"]),
});
