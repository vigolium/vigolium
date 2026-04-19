import { defineSchema, defineTable } from 'convex/server';
import { v } from 'convex/values';

export default defineSchema({
  users: defineTable({
    email: v.string(),
    workosUserId: v.string(),
    status: v.union(
      v.literal('active'),
      v.literal('suspended'),
      v.literal('pending'),
    ),
    allowedAt: v.number(),
    lastLoginAt: v.number(),
    loginCount: v.number(),
    role: v.union(
      v.literal('admin'),
      v.literal('member'),
      v.literal('viewer'),
    ),
  })
    .index('by_email', ['email'])
    .index('by_workosId', ['workosUserId']),

  creditLedger: defineTable({
    userId: v.id('users'),
    amount: v.number(),
    reason: v.union(
      v.literal('purchase'),
      v.literal('scan'),
      v.literal('refund'),
      v.literal('grant'),
    ),
    endpoint: v.optional(v.string()),
    balanceAfter: v.number(),
  }).index('by_user', ['userId']),

  projectAccess: defineTable({
    userId: v.id('users'),
    projectUuid: v.string(),
    role: v.union(
      v.literal('owner'),
      v.literal('editor'),
      v.literal('viewer'),
    ),
    grantedBy: v.optional(v.id('users')),
    grantedAt: v.number(),
  })
    .index('by_user', ['userId'])
    .index('by_project', ['projectUuid'])
    .index('by_user_project', ['userId', 'projectUuid']),

  quotas: defineTable({
    userId: v.id('users'),
    dailyScanLimit: v.number(),
    concurrentScanLimit: v.number(),
    currentDailyUsage: v.number(),
    lastResetAt: v.number(),
  }).index('by_user', ['userId']),

  auditLog: defineTable({
    userId: v.optional(v.id('users')),
    userEmail: v.optional(v.string()),
    action: v.string(),
    resource: v.optional(v.string()),
    metadata: v.optional(v.any()),
  }).index('by_user', ['userId']),
});
