import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

export default defineSchema({
  users: defineTable({
    name: v.string(),
    email: v.string(),
    avatar: v.optional(v.string()),
  }).index("by_email", ["email"]),

  threads: defineTable({
    title: v.string(),
    ownerId: v.string(), // userId
    createdAt: v.number(),
  }).index("by_owner", ["ownerId"]),
});
