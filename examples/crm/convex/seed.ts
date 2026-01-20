import { mutation } from "./_generated/server";
import { authz } from "./authz";

export const run = mutation({
    args: {},
    handler: async (ctx) => {
        // 1. Clean up (Simple truncation for demo)
        for (const table of ["users", "orgs", "contacts", "deals"] as const) {
            const docs = await ctx.db.query(table).collect();
            for (const d of docs) await ctx.db.delete(d._id);
        }

        // 2. Create Users
        const aliceId = await ctx.db.insert("users", { name: "Alice Owner", email: "alice@acme.com" });
        const bobId = await ctx.db.insert("users", { name: "Bob Member", email: "bob@acme.com" });

        // 3. Create Orgs
        const acmeId = await ctx.db.insert("orgs", { name: "Acme Corp", slug: "acme", plan: "enterprise" });
        const orgScope = { type: "org", id: acmeId };

        // 4. Assign Roles (Scoped)
        // Alice is Owner of Acme
        await authz.assignRole(ctx, aliceId, "org:owner", orgScope);

        // Bob is Member of Acme
        await authz.assignRole(ctx, bobId, "org:member", orgScope);

        // 5. Create Data
        await ctx.db.insert("contacts", { orgId: acmeId, name: "Important Client", email: "client@example.com" });
        await ctx.db.insert("deals", { orgId: acmeId, title: "Big Contract", value: 100000, stage: "negotiation" });

        return "CRM Seeded!";
    },
});
