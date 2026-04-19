import { mutation, query } from './_generated/server';
import { v } from 'convex/values';

export const getBalance = query({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }) => {
    const latest = await ctx.db
      .query('creditLedger')
      .withIndex('by_user', (q) => q.eq('userId', userId))
      .order('desc')
      .first();
    return latest?.balanceAfter ?? 0;
  },
});

export const deduct = mutation({
  args: {
    userId: v.id('users'),
    cost: v.number(),
    endpoint: v.string(),
  },
  handler: async (ctx, { userId, cost, endpoint }) => {
    const user = await ctx.db.get(userId);
    if (!user) throw new Error('User not found');

    const latest = await ctx.db
      .query('creditLedger')
      .withIndex('by_user', (q) => q.eq('userId', userId))
      .order('desc')
      .first();

    const balance = latest?.balanceAfter ?? 0;
    if (balance < cost) {
      return { success: false, remaining: balance };
    }

    const newBalance = balance - cost;
    await ctx.db.insert('creditLedger', {
      userId,
      amount: -cost,
      reason: 'scan',
      endpoint,
      balanceAfter: newBalance,
    });

    return { success: true, remaining: newBalance };
  },
});

export const addCredits = mutation({
  args: {
    userId: v.id('users'),
    amount: v.number(),
    reason: v.union(
      v.literal('purchase'),
      v.literal('refund'),
      v.literal('grant'),
    ),
  },
  handler: async (ctx, { userId, amount, reason }) => {
    const latest = await ctx.db
      .query('creditLedger')
      .withIndex('by_user', (q) => q.eq('userId', userId))
      .order('desc')
      .first();

    const balance = latest?.balanceAfter ?? 0;
    const newBalance = balance + amount;
    await ctx.db.insert('creditLedger', {
      userId,
      amount,
      reason,
      balanceAfter: newBalance,
    });

    return { balance: newBalance };
  },
});

export const getLedger = query({
  args: {
    userId: v.id('users'),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, { userId, limit }) => {
    const q = ctx.db
      .query('creditLedger')
      .withIndex('by_user', (q) => q.eq('userId', userId))
      .order('desc');

    if (limit) {
      return q.take(limit);
    }
    return q.collect();
  },
});
