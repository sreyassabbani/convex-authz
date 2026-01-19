/**
 * App Queries and Mutations for the Demo UI
 *
 * These functions provide data for the frontend dashboard.
 */

import { mutation, query, type QueryCtx, type MutationCtx } from "./_generated/server.js";
import { components } from "./_generated/api.js";
import { defineAuthz, type Scope } from "@djpanda/convex-authz";
import { v } from "convex/values";
import { Auth } from "convex/server";
import { DataModel } from "./_generated/dataModel.js";

// ============================================================================
// Step 1: Define your Permissions and Roles in one place
// ============================================================================

export const authz = defineAuthz(components.authz, {
  permissions: {
    documents: ["create", "read", "update", "delete"],
    settings: ["view", "manage"],
    users: ["invite", "remove", "manage"],
    billing: ["view", "manage"],
  },
  roles: {
    // Global Roles
    admin: {
      permissions: ["documents:*", "settings:*", "users:*", "billing:*"],
      label: "Global Admin",
      description: "Full access to all resources across all orgs",
    },
    // Scoped Orgs Roles
    "org:admin": {
      permissions: ["documents:*", "settings:*", "users:*"],
      label: "Org Admin",
      description: "Full administrative access within an organization",
    },
    "org:member": {
      permissions: ["documents:read", "documents:create", "settings:view"],
      label: "Org Member",
      description: "Read/Write access to documents within an organization",
    },
  },
});

// ============================================================================
// Queries
// ============================================================================

export const listUsers = query({
  args: {},
  handler: async (ctx) => {
    return await ctx.db.query("users").collect();
  },
});

export const listOrgs = query({
  args: {},
  handler: async (ctx) => {
    return await ctx.db.query("orgs").collect();
  },
});

export const listDocuments = query({
  args: {},
  handler: async (ctx) => {
    return await ctx.db.query("documents").collect();
  },
});

export const getUserWithRoles = query({
  args: { userId: v.id("users") },
  returns: v.union(
    v.object({
      user: v.object({
        _id: v.id("users"),
        _creationTime: v.number(),
        name: v.string(),
        email: v.string(),
        avatar: v.optional(v.string()),
      }),
      roles: v.array(
        v.object({
          role: v.string(),
          scope: v.optional(v.object({ type: v.string(), id: v.string() })),
          expiresAt: v.optional(v.number()),
        })
      ),
      orgs: v.array(
        v.object({
          _id: v.id("orgs"),
          name: v.string(),
          slug: v.string(),
        })
      ),
    }),
    v.null()
  ),
  handler: async (ctx: QueryCtx, args) => {
    const user = await ctx.db.get(args.userId);
    if (!user) return null;

    const roles = await authz.getUserRoles(ctx, String(args.userId));

    // Get user's orgs
    const memberships = await ctx.db
      .query("org_members")
      .withIndex("by_user", (q) => q.eq("userId", args.userId))
      .collect();

    const orgs = await Promise.all(
      memberships.map(async (m) => {
        const org = await ctx.db.get(m.orgId);
        return org
          ? { _id: org._id, name: org.name, slug: org.slug }
          : null;
      })
    );

    return {
      user,
      roles,
      orgs: orgs.filter((o): o is NonNullable<typeof o> => o !== null),
    };
  },
});

export const getRoleDefinitions = query({
  args: {},
  returns: v.array(
    v.object({
      name: authz.validators.role,
      label: v.string(),
      description: v.string(),
      permissions: v.array(v.string()),
    })
  ),
  handler: async () => {
    // Transform the config into a list for the UI
    return Object.entries(authz.config.roles).map(([name, def]) => ({
      name: name as any,
      label: def.label ?? name,
      description: def.description ?? "",
      permissions: def.permissions,
    }));
  },
});

export const getStats = query({
  args: {},
  returns: v.object({
    users: v.number(),
    orgs: v.number(),
    documents: v.number(),
    roleAssignments: v.number(),
  }),
  handler: async (ctx) => {
    const users = await ctx.db.query("users").collect();
    const orgs = await ctx.db.query("orgs").collect();
    const documents = await ctx.db.query("documents").collect();

    // Count role assignments by querying authz for each user
    let roleAssignments = 0;
    for (const user of users) {
      const roles = await authz.getUserRoles(ctx, String(user._id));
      roleAssignments += roles.length;
    }

    return {
      users: users.length,
      orgs: orgs.length,
      documents: documents.length,
      roleAssignments,
    };
  },
});

// ============================================================================
// Permission Checking
// ============================================================================

export const checkPermission = query({
  args: {
    userId: v.id("users"),
    permission: authz.validators.permission,
    orgId: v.optional(v.id("orgs")),
  },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    const scope: Scope | undefined = args.orgId
      ? { type: "org", id: String(args.orgId) }
      : undefined;
    return await authz.can(ctx, String(args.userId), args.permission, scope);
  },
});

export const checkAllPermissions = query({
  args: {
    userId: v.id("users"),
    orgId: v.optional(v.id("orgs")),
  },
  returns: v.record(v.string(), v.boolean()),
  handler: async (ctx, args) => {
    const scope: Scope | undefined = args.orgId
      ? { type: "org", id: String(args.orgId) }
      : undefined;

    const perms = [
      "documents:create",
      "documents:read",
      "documents:update",
      "documents:delete",
      "settings:view",
      "settings:manage",
      "users:invite",
      "users:remove",
      "users:manage",
      "billing:view",
      "billing:manage",
    ] as const;

    const results: Record<string, boolean> = {};
    for (const perm of perms) {
      results[perm] = await authz.can(ctx, String(args.userId), perm, scope);
    }

    return results;
  },
});

// ============================================================================
// Mutations
// ============================================================================

export const assignRole = mutation({
  args: {
    userId: v.id("users"),
    role: authz.validators.role,
    orgId: v.optional(v.id("orgs")),
  },
  returns: v.string(),
  handler: async (ctx: MutationCtx, args) => {
    // For scoped roles, pass the scopeId as the parameter
    if (args.role.startsWith("org:")) {
      if (!args.orgId) throw new Error("orgId is required for org roles");
      return await (authz.assignRole as any)(ctx, String(args.userId), args.role, String(args.orgId));
    }

    return await (authz.assignRole as any)(ctx, String(args.userId), args.role);
  },
});

export const revokeRole = mutation({
  args: {
    userId: v.id("users"),
    role: authz.validators.role,
    orgId: v.optional(v.id("orgs")),
  },
  returns: v.boolean(),
  handler: async (ctx: MutationCtx, args) => {
    if (args.role.startsWith("org:")) {
      if (!args.orgId) throw new Error("orgId is required for org roles");
      return await (authz.revokeRole as any)(ctx, String(args.userId), args.role, String(args.orgId));
    }
    return await (authz.revokeRole as any)(ctx, String(args.userId), args.role);
  },
});

// ============================================================================
// Helper function to get authenticated user ID
// ============================================================================
async function getAuthUserId(ctx: { auth: Auth }): Promise<string> {
  const identity = await ctx.auth.getUserIdentity();
  if (!identity) {
    throw new Error("Unauthorized: User must be authenticated");
  }
  return identity.subject;
}
