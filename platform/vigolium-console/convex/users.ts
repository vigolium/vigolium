import { mutation, query } from './_generated/server';
import { v } from 'convex/values';

export const upsertOnLogin = mutation({
  args: {
    email: v.string(),
    workosUserId: v.string(),
  },
  handler: async (ctx, { email, workosUserId }) => {
    const existing = await ctx.db
      .query('users')
      .withIndex('by_workosId', (q) => q.eq('workosUserId', workosUserId))
      .unique();

    const now = Date.now();

    if (existing) {
      await ctx.db.patch(existing._id, {
        lastLoginAt: now,
        loginCount: existing.loginCount + 1,
        email,
      });

      const projects = await ctx.db
        .query('projectAccess')
        .withIndex('by_user', (q) => q.eq('userId', existing._id))
        .collect();

      return {
        userId: existing._id,
        status: existing.status,
        isNew: false,
        projects: projects.map((p) => p.projectUuid),
      };
    }

    const userId = await ctx.db.insert('users', {
      email,
      workosUserId,
      status: 'active',
      allowedAt: now,
      lastLoginAt: now,
      loginCount: 1,
      role: 'member',
    });

    return {
      userId,
      status: 'active' as const,
      isNew: true,
      projects: [] as string[],
    };
  },
});

export const getByWorkosId = query({
  args: { workosUserId: v.string() },
  handler: async (ctx, { workosUserId }) => {
    return ctx.db
      .query('users')
      .withIndex('by_workosId', (q) => q.eq('workosUserId', workosUserId))
      .unique();
  },
});

export const getByEmail = query({
  args: { email: v.string() },
  handler: async (ctx, { email }) => {
    return ctx.db
      .query('users')
      .withIndex('by_email', (q) => q.eq('email', email))
      .unique();
  },
});

export const list = query({
  handler: async (ctx) => {
    return ctx.db.query('users').collect();
  },
});

export const updateStatus = mutation({
  args: {
    userId: v.id('users'),
    status: v.union(
      v.literal('active'),
      v.literal('suspended'),
      v.literal('pending'),
    ),
  },
  handler: async (ctx, { userId, status }) => {
    await ctx.db.patch(userId, { status });
  },
});

export const updateRole = mutation({
  args: {
    userId: v.id('users'),
    role: v.union(
      v.literal('admin'),
      v.literal('member'),
      v.literal('viewer'),
    ),
  },
  handler: async (ctx, { userId, role }) => {
    await ctx.db.patch(userId, { role });
  },
});
