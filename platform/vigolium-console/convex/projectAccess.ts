import { mutation, query } from './_generated/server';
import { v } from 'convex/values';

export const grant = mutation({
  args: {
    userId: v.id('users'),
    projectUuid: v.string(),
    role: v.union(
      v.literal('owner'),
      v.literal('editor'),
      v.literal('viewer'),
    ),
    grantedBy: v.optional(v.id('users')),
  },
  handler: async (ctx, { userId, projectUuid, role, grantedBy }) => {
    const existing = await ctx.db
      .query('projectAccess')
      .withIndex('by_user_project', (q) =>
        q.eq('userId', userId).eq('projectUuid', projectUuid),
      )
      .unique();

    if (existing) {
      await ctx.db.patch(existing._id, { role, grantedBy });
      return existing._id;
    }

    return ctx.db.insert('projectAccess', {
      userId,
      projectUuid,
      role,
      grantedBy,
      grantedAt: Date.now(),
    });
  },
});

export const revoke = mutation({
  args: {
    userId: v.id('users'),
    projectUuid: v.string(),
  },
  handler: async (ctx, { userId, projectUuid }) => {
    const access = await ctx.db
      .query('projectAccess')
      .withIndex('by_user_project', (q) =>
        q.eq('userId', userId).eq('projectUuid', projectUuid),
      )
      .unique();

    if (access) {
      await ctx.db.delete(access._id);
    }
  },
});

export const listForUser = query({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }) => {
    return ctx.db
      .query('projectAccess')
      .withIndex('by_user', (q) => q.eq('userId', userId))
      .collect();
  },
});

export const listForProject = query({
  args: { projectUuid: v.string() },
  handler: async (ctx, { projectUuid }) => {
    return ctx.db
      .query('projectAccess')
      .withIndex('by_project', (q) => q.eq('projectUuid', projectUuid))
      .collect();
  },
});

export const checkAccess = query({
  args: {
    userId: v.id('users'),
    projectUuid: v.string(),
  },
  handler: async (ctx, { userId, projectUuid }) => {
    const access = await ctx.db
      .query('projectAccess')
      .withIndex('by_user_project', (q) =>
        q.eq('userId', userId).eq('projectUuid', projectUuid),
      )
      .unique();

    return access
      ? { hasAccess: true, role: access.role }
      : { hasAccess: false, role: null };
  },
});
