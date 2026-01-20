import { v } from "convex/values";
import { mutation, query } from "./_generated/server";
import { authz } from "./authz";

/**
 * CRM: Create a new contact within an Organization.
 */
export const create = mutation({
    args: {
        orgId: v.string(), // Tenants are identified by string IDs
        name: v.string(),
        email: v.string(),
    },
    handler: async (ctx, args) => {
        const userId = "user123";
        const orgScope = { type: "org", id: args.orgId };

        // Check if user has permission in THIS specific organization
        if (!(await authz.can(ctx, userId, "contacts:create", orgScope))) {
            throw new Error("Unauthorized: Cannot create contacts in this organization");
        }

        // Logic...
        console.log(`Creating contact ${args.name} for org ${args.orgId}`);
    },
});
