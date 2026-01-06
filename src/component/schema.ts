import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

/**
 * Authz Component Schema
 *
 * This schema defines tables for RBAC/ABAC authorization.
 * All userId and resourceId fields are strings because they reference
 * the parent app's tables.
 */
export default defineSchema({
  // Role assignments table - maps users to roles
  // Roles can be global or scoped to a specific resource
  roleAssignments: defineTable({
    userId: v.string(), // References parent app's users table
    role: v.string(), // Role name (e.g., "admin", "editor", "viewer")
    // Optional scope for resource-level role assignments
    scope: v.optional(
      v.object({
        type: v.string(), // Resource type (e.g., "document", "project")
        id: v.string(), // Resource ID
      })
    ),
    // Optional metadata for additional context
    metadata: v.optional(v.any()),
    // Who assigned this role
    assignedBy: v.optional(v.string()),
    // When this role assignment expires (null = never)
    expiresAt: v.optional(v.number()),
  })
    .index("by_user", ["userId"])
    .index("by_role", ["role"])
    .index("by_user_and_role", ["userId", "role"]),

  // User attributes table - stores user attributes for ABAC
  // Attributes can be used in policy conditions
  userAttributes: defineTable({
    userId: v.string(), // References parent app's users table
    key: v.string(), // Attribute key (e.g., "department", "clearanceLevel")
    value: v.any(), // Attribute value (can be string, number, boolean, array, object)
  })
    .index("by_user", ["userId"])
    .index("by_user_and_key", ["userId", "key"]),

  // Permission overrides - explicit grants or denials for specific permissions
  // These take precedence over role-based permissions
  permissionOverrides: defineTable({
    userId: v.string(), // References parent app's users table
    permission: v.string(), // Permission string (e.g., "documents:read")
    effect: v.union(v.literal("allow"), v.literal("deny")), // Grant or deny
    // Optional scope for resource-level overrides
    scope: v.optional(
      v.object({
        type: v.string(), // Resource type
        id: v.string(), // Resource ID
      })
    ),
    // Reason for the override
    reason: v.optional(v.string()),
    // Who created this override
    createdBy: v.optional(v.string()),
    // When this override expires (null = never)
    expiresAt: v.optional(v.number()),
  })
    .index("by_user", ["userId"])
    .index("by_user_and_permission", ["userId", "permission"]),

  // Relationships table - for ReBAC (Relationship-Based Access Control)
  // Stores tuples like (user:123, member, team:456)
  relationships: defineTable({
    subjectType: v.string(), // e.g., "user", "team", "account"
    subjectId: v.string(), // ID of the subject
    relation: v.string(), // e.g., "member", "owner", "viewer", "parent"
    objectType: v.string(), // e.g., "team", "account", "deal"
    objectId: v.string(), // ID of the object
    createdBy: v.optional(v.string()),
    createdAt: v.number(),
  })
    .index("by_subject", ["subjectType", "subjectId"])
    .index("by_object", ["objectType", "objectId"])
    .index("by_subject_relation_object", [
      "subjectType",
      "subjectId",
      "relation",
      "objectType",
      "objectId",
    ])
    .index("by_object_relation", ["objectType", "objectId", "relation"]),

  // =========================================================================
  // O(1) Indexed Tables - Pre-computed permissions for fast lookups
  // =========================================================================

  // Effective permissions - denormalized for O(1) lookup
  effectivePermissions: defineTable({
    userId: v.string(),
    permission: v.string(), // e.g., "documents:read"
    scopeKey: v.string(), // "global" or "document:123"
    scope: v.optional(v.object({ type: v.string(), id: v.string() })),
    effect: v.string(), // "allow" or "deny"
    // Which roles/sources granted this permission
    sources: v.array(v.string()),
    // Direct grant/deny (not from role)
    directGrant: v.optional(v.boolean()),
    directDeny: v.optional(v.boolean()),
    reason: v.optional(v.string()),
    grantedBy: v.optional(v.string()),
    expiresAt: v.optional(v.number()),
    createdAt: v.number(),
    updatedAt: v.number(),
  })
    .index("by_user", ["userId"])
    .index("by_user_scope", ["userId", "scopeKey"])
    .index("by_user_permission_scope", ["userId", "permission", "scopeKey"]),

  // Effective roles - denormalized for O(1) lookup
  effectiveRoles: defineTable({
    userId: v.string(),
    role: v.string(),
    scopeKey: v.string(), // "global" or "team:123"
    scope: v.optional(v.object({ type: v.string(), id: v.string() })),
    assignedBy: v.optional(v.string()),
    expiresAt: v.optional(v.number()),
    createdAt: v.number(),
    updatedAt: v.number(),
  })
    .index("by_user", ["userId"])
    .index("by_user_scope", ["userId", "scopeKey"])
    .index("by_user_role_scope", ["userId", "role", "scopeKey"]),

  // Effective relationships - pre-computed transitive relations
  effectiveRelationships: defineTable({
    subjectKey: v.string(), // "user:123" or "team:456"
    subjectType: v.string(),
    subjectId: v.string(),
    relation: v.string(),
    objectKey: v.string(), // "account:789"
    objectType: v.string(),
    objectId: v.string(),
    isDirect: v.boolean(),
    inheritedFrom: v.union(v.string(), v.null()), // ID of the relationship this was inherited from
    createdBy: v.optional(v.string()),
    createdAt: v.number(),
  })
    .index("by_subject", ["subjectKey"])
    .index("by_object", ["objectKey"])
    .index("by_subject_relation", ["subjectKey", "relation"])
    .index("by_subject_relation_object", ["subjectKey", "relation", "objectKey"])
    .index("by_inherited_from", ["inheritedFrom"]),

  // Audit log - optional trail of permission checks and changes
  auditLog: defineTable({
    timestamp: v.number(),
    action: v.union(
      v.literal("permission_check"),
      v.literal("role_assigned"),
      v.literal("role_revoked"),
      v.literal("permission_granted"),
      v.literal("permission_denied"),
      v.literal("attribute_set"),
      v.literal("attribute_removed")
    ),
    userId: v.string(), // The user the action was performed on
    actorId: v.optional(v.string()), // Who performed the action
    details: v.object({
      permission: v.optional(v.string()),
      role: v.optional(v.string()),
      result: v.optional(v.boolean()),
      scope: v.optional(
        v.object({
          type: v.string(),
          id: v.string(),
        })
      ),
      attribute: v.optional(
        v.object({
          key: v.string(),
          value: v.optional(v.any()),
        })
      ),
      reason: v.optional(v.string()),
    }),
  })
    .index("by_user", ["userId"])
    .index("by_action", ["action"])
    .index("by_timestamp", ["timestamp"]),
});
