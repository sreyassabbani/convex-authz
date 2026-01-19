/**
 * App Queries and Mutations for the Demo UI
 *
 * These functions provide data for the frontend dashboard.
 */

import { mutation, query, type QueryCtx, type MutationCtx } from "./_generated/server.js";
import { components } from "./_generated/api.js";
import {
  Authz,
  definePermissions,
  defineRoles,
  defineAuthzConfig,
  AnyRole,
  GlobalRole,
  AnyPermission,
} from "@djpanda/convex-authz";
import { v, type Validator } from "convex/values";
import { Auth } from "convex/server";

// ============================================================================
// Step 1: Define your permissions
// ============================================================================
const permissions = definePermissions({
  documents: { create: true, read: true, update: true, delete: true },
  settings: { view: true, manage: true },
  users: { invite: true, remove: true, manage: true },
  billing: { view: true, manage: true },
});

// ============================================================================
// Step 2: Define roles for each scope
// ============================================================================
const globalRoles = defineRoles(permissions, {
  admin: {
    documents: ["create", "read", "update", "delete"],
    settings: ["view", "manage"],
    users: ["invite", "remove", "manage"],
    billing: ["view", "manage"],
  },
});

const orgRoles = defineRoles(permissions, {
  admin: {
    documents: ["create", "read", "update", "delete"],
    settings: ["view"],
    users: ["invite", "remove"],
  },
  member: {
    documents: ["read", "create"],
    settings: ["view"],
  },
});

// ============================================================================
// Step 3: Combine into a full Authz config
// ============================================================================
const authzConfig = defineAuthzConfig({
  permissions,
  roles: {
    global: globalRoles,
    org: orgRoles,
  },
});

const authz = new Authz(components.authz, { config: authzConfig });

// ============================================================================
// Queries
// ============================================================================

export const listUsers = query({
  args: {},
  returns: v.array(
    v.object({
      _id: v.id("users"),
      _creationTime: v.number(),
      name: v.string(),
      email: v.string(),
      avatar: v.optional(v.string()),
    })
  ),
  handler: async (ctx) => {
    return await ctx.db.query("users").collect();
  },
});

export const listOrgs = query({
  args: {},
  returns: v.array(
    v.object({
      _id: v.id("orgs"),
      _creationTime: v.number(),
      name: v.string(),
      slug: v.string(),
      plan: v.string(),
    })
  ),
  handler: async (ctx) => {
    return await ctx.db.query("orgs").collect();
  },
});

export const listDocuments = query({
  args: {},
  returns: v.array(
    v.object({
      _id: v.id("documents"),
      _creationTime: v.number(),
      title: v.string(),
      content: v.optional(v.string()),
      orgId: v.id("orgs"),
      authorId: v.id("users"),
    })
  ),
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
          _id: v.string(),
          role: v.string(),
          scope: v.optional(v.object({ type: v.string(), id: v.string() })),
          expiresAt: v.optional(v.number()),
          metadata: v.optional(v.any()),
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
      name: v.string() as Validator<AnyRole<typeof authzConfig>>,
      label: v.string(),
      description: v.string(),
      permissions: v.array(v.string()),
    })
  ),
  handler: async () => {
    return [
      {
        name: "global:admin" as AnyRole<typeof authzConfig>,
        label: "Global Admin",
        description: "Full access to all resources across all orgs",
        permissions: ["*"],
      },
      {
        name: "org:admin" as AnyRole<typeof authzConfig>,
        label: "Org Admin",
        description: "Full administrative access within an organization",
        permissions: ["documents:*", "settings:*", "users:*"],
      },
      {
        name: "org:member" as AnyRole<typeof authzConfig>,
        label: "Org Member",
        description: "Read/Write access to documents within an organization",
        permissions: ["documents:read", "documents:create", "settings:view"],
      },
    ];
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
    permission: v.string() as Validator<AnyPermission<typeof authzConfig>>,
    orgId: v.optional(v.id("orgs")),
  },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    const scope = args.orgId
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
    const scope = args.orgId
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
    role: v.string() as Validator<AnyRole<typeof authzConfig>>, // Strictly typed
    orgId: v.optional(v.id("orgs")),
  },
  returns: v.string(),
  handler: async (ctx: MutationCtx, args) => {
    const role = args.role;
    if (role.includes(":")) {
      const orgId = args.orgId ? String(args.orgId) : "";
      return await authz.assignRole(
        ctx,
        String(args.userId),
        role,
        orgId
      );
    } else {
      return await authz.assignRole(
        ctx,
        String(args.userId),
        role as GlobalRole<typeof authzConfig>
      );
    }
  },
});

export const revokeRole = mutation({
  args: {
    userId: v.id("users"),
    role: v.string() as Validator<AnyRole<typeof authzConfig>>,
    orgId: v.optional(v.id("orgs")),
  },
  returns: v.boolean(),
  handler: async (ctx: MutationCtx, args) => {
    const role = args.role;
    if (role.includes(":")) {
      const orgId = args.orgId ? String(args.orgId) : "";
      return await authz.revokeRole(
        ctx,
        String(args.userId),
        role,
        orgId
      );
    } else {
      return await authz.revokeRole(
        ctx,
        String(args.userId),
        role as GlobalRole<typeof authzConfig>
      );
    }
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
