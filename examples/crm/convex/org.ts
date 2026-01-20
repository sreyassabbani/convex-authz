import { v } from "convex/values";
import { mutation, query } from "./_generated/server";
import { authz, P } from "./authz";

/**
 * CRM: Create a custom role for an Organization (e.g. "Sales Manager")
 * This demonstrates the Dynamic Roles feature.
 */
export const createRole = mutation({
    args: {
        orgId: v.string(),
        roleName: v.string(), // e.g., "sales_manager"
        permissions: v.array(v.string()), // e.g., ["contacts:*", "deals:create"]
        parentRole: v.optional(v.string()), // e.g., "org:member"
    },
    handler: async (ctx, args) => {
        const userId = "user123";
        const orgScope = { type: "org", id: args.orgId };

        // Only org owners can create new roles
        if (!(await authz.can(userId).perform(P.org.manage_members).in(orgScope).check(ctx))) {
            throw new Error("Unauthorized");
        }

        // Create the role scoped to this org
        // Note: In a real app we might validate 'args.permissions' to ensure they are valid patterns
        await authz.createRole(ctx, orgScope, {
            name: args.roleName,
            permissions: args.permissions,
            parentRole: args.parentRole,
            label: args.roleName, // Use name as label for now
        });
    },
});

/**
 * CRM: Assign a user to a custom role
 */
export const assignRole = mutation({
    args: {
        orgId: v.string(),
        targetUserId: v.string(),
        roleName: v.string(), // Could be "org:member" OR "sales_manager" (dynamic)
    },
    handler: async (ctx, args) => {
        const userId = "user123";
        const orgScope = { type: "org", id: args.orgId };

        if (!(await authz.can(userId).perform(P.org.manage_members).in(orgScope).check(ctx))) {
            throw new Error("Unauthorized");
        }

        // Assign role scoped to this org
        await authz.assignRole(ctx, args.targetUserId, args.roleName, orgScope);
    },
});

/**
 * CRM: Check specific permission (Helper for UI)
 */
export const checkAccess = query({
    args: { orgId: v.string() },
    handler: async (ctx, args) => {
        const userId = "user123";
        const orgScope = { type: "org", id: args.orgId };

        return {
            canViewDeals: await authz.can(userId).perform(P.deals.read).in(orgScope).check(ctx),
            canCloseDeals: await authz.can(userId).perform(P.deals.close).in(orgScope).check(ctx),
            canManageBilling: await authz.can(userId).perform(P.org.manage_billing).in(orgScope).check(ctx),
        };
    },
});
