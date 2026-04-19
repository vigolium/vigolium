import { mutation, query } from './_generated/server';
import { v } from 'convex/values';

const DEFAULT_DAILY_LIMIT = 100;
const DEFAULT_CONCURRENT_LIMIT = 5;
const ONE_DAY_MS = 24 * 60 * 60 * 1000;

export const get = query({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }) => {
    return ctx.db
      .query('quotas')
      .withIndex('by_user', (q) => q.eq('userId', userId))
      .unique();
  },
});

export const checkAndIncrement = mutation({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }) => {
    let quota = await ctx.db
      .query('quotas')
      .withIndex('by_user', (q) => q.eq('userId', userId))
      .unique();

    if (!quota) {
      const id = await ctx.db.insert('quotas', {
        userId,
        dailyScanLimit: DEFAULT_DAILY_LIMIT,
        concurrentScanLimit: DEFAULT_CONCURRENT_LIMIT,
        currentDailyUsage: 1,
        lastResetAt: Date.now(),
      });
      return { allowed: true, quotaId: id };
    }

    const now = Date.now();
    let usage = quota.currentDailyUsage;

    if (now - quota.lastResetAt > ONE_DAY_MS) {
      usage = 0;
      await ctx.db.patch(quota._id, { currentDailyUsage: 0, lastResetAt: now });
    }

    if (usage >= quota.dailyScanLimit) {
      return { allowed: false, reason: 'Daily scan limit reached' };
    }

    await ctx.db.patch(quota._id, { currentDailyUsage: usage + 1 });
    return { allowed: true };
  },
});

export const update = mutation({
  args: {
    userId: v.id('users'),
    dailyScanLimit: v.optional(v.number()),
    concurrentScanLimit: v.optional(v.number()),
  },
  handler: async (ctx, { userId, dailyScanLimit, concurrentScanLimit }) => {
    const quota = await ctx.db
      .query('quotas')
      .withIndex('by_user', (q) => q.eq('userId', userId))
      .unique();

    if (!quota) throw new Error('Quota not found');

    const patch: Record<string, number> = {};
    if (dailyScanLimit !== undefined) patch.dailyScanLimit = dailyScanLimit;
    if (concurrentScanLimit !== undefined)
      patch.concurrentScanLimit = concurrentScanLimit;

    await ctx.db.patch(quota._id, patch);
  },
});
