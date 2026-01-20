import { mutation } from "./_generated/server";
import { authz } from "./authz";

export const run = mutation({
    args: {},
    handler: async (ctx) => {
        // 1. Clean up
        const existingUsers = await ctx.db.query("users").collect();
        for (const u of existingUsers) await ctx.db.delete(u._id);

        const existingThreads = await ctx.db.query("threads").collect();
        for (const t of existingThreads) await ctx.db.delete(t._id);

        // 2. Create Users
        const adminId = await ctx.db.insert("users", { name: "Admin User", email: "admin@example.com" });
        const userId = await ctx.db.insert("users", { name: "Regular User", email: "user@example.com" });

        // 3. Assign Roles (Global)
        // admin gets 'admin' role
        await authz.assignRole(ctx, adminId, "admin");

        // regular user gets 'user' role
        await authz.assignRole(ctx, userId, "user");

        // 4. Create Threads
        await ctx.db.insert("threads", {
            title: "Welcome Thread",
            ownerId: adminId,
            createdAt: Date.now()
        });

        await ctx.db.insert("threads", {
            title: "My First Thread",
            ownerId: userId,
            createdAt: Date.now()
        });

        return "Chatbot Seeded!";
    },
});
