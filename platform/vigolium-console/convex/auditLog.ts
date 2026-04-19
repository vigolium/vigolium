import { mutation, query } from './_generated/server';
import { v } from 'convex/values';

export const log = mutation({
  args: {
    userId: v.optional(v.id('users')),
    userEmail: v.optional(v.string()),
    action: v.string(),
    resource: v.optional(v.string()),
    metadata: v.optional(v.any()),
  },
  handler: async (ctx, args) => {
    return ctx.db.insert('auditLog', args);
  },
});

export const list = query({
  args: {
    limit: v.optional(v.number()),
  },
  handler: async (ctx, { limit }) => {
    const q = ctx.db.query('auditLog').order('desc');
    if (limit) {
      return q.take(limit);
    }
    return q.take(100);
  },
});

export const listForUser = query({
  args: {
    userId: v.id('users'),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, { userId, limit }) => {
    const q = ctx.db
      .query('auditLog')
      .withIndex('by_user', (q) => q.eq('userId', userId))
      .order('desc');

    if (limit) {
      return q.take(limit);
    }
    return q.take(100);
  },
});
