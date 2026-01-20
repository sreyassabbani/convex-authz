import { v } from "convex/values";
import { mutation, query } from "./_generated/server";
import { authz, P } from "./authz";

/**
 * List threads user can see.
 */
export const list = query({
    args: {},
    handler: async (ctx) => {
        // In a real app, we'd get userId from ctx.auth
        const userId = "user123";

        // Admin can see everything
        if (await authz.can(userId).perform(P.admin.manage).check(ctx)) {
            return ctx.db.query("threads").collect();
        }

        // Regular users see their own threads
        if (await authz.can(userId).perform(P.threads.read).check(ctx)) {
            return ctx.db.query("threads")
                .filter(q => q.eq(q.field("ownerId"), userId))
                .collect();
        }

        return [];
    },
});

/**
 * Create a thread.
 */
export const create = mutation({
    args: { title: v.string() },
    handler: async (ctx, args) => {
        const userId = "user123";

        if (!(await authz.can(userId).perform(P.threads.create).check(ctx))) {
            throw new Error("Unauthorized");
        }

        return ctx.db.insert("threads", {
            title: args.title,
            ownerId: userId,
            createdAt: Date.now(),
        });
    },
});

/**
 * Delete a thread.
 */
export const deleteThread = mutation({
    args: { threadId: v.id("threads") },
    handler: async (ctx, args) => {
        const userId = "user123";
        const thread = await ctx.db.get(args.threadId);
        if (!thread) throw new Error("Not found");

        if (await authz.can(userId).perform(P.admin.manage).check(ctx)) {
            await ctx.db.delete(args.threadId);
            return;
        }

        if (thread.ownerId === userId && await authz.can(userId).perform(P.threads.delete).check(ctx)) {
            await ctx.db.delete(args.threadId);
            return;
        }

        throw new Error("Unauthorized");
    },
});
