# Convex Integration Plan for Vigolium Console

## Current State

| Concern | Current Solution | Limitation |
|---------|-----------------|------------|
| User identity | WorkOS (no local DB) | No local user table, can't easily query/filter users |
| Credits | Stripe customer metadata (`credits` field) | Not transactional, no usage history, no per-action logs |
| Team membership | WorkOS org API | No role enforcement, single-org assumption |
| User allowlisting | `console-users.json` file + `allowed_emails` on projects | Static file, requires redeploy to change |
| Usage tracking | None — credit deductions are fire-and-forget | Can't answer "who used what, when" |
| Payment history | Stripe checkout sessions query | Only purchases, not consumption |

## What Convex Will Own

### 1. User Registry & Access Control

```
users: {
  email, workosUserId, status (active/suspended/pending),
  allowedAt, lastLoginAt, role (admin/member/viewer)
}
```

- Replace `console-users.json` with a live, queryable table
- Admin dashboard to approve/suspend users instantly (reactive — no redeploy)
- Track last login, login count

### 2. Credits & Usage Ledger

```
creditLedger: {
  userId, amount (+/-), reason (purchase/scan/refund),
  endpoint, timestamp, balanceAfter
}
```

- Every credit change is an append-only ledger entry
- Current balance = sum of ledger (or cached on user record)
- Full audit trail: "user X spent 5 credits on `/api/scan-url` at 14:32"
- Convex mutations are transactional — no race conditions on deductions

### 3. User-Project Mapping

```
projectAccess: {
  userId, projectUuid, role (owner/editor/viewer), grantedBy, grantedAt
}
```

- Replace `allowed_emails`/`allowed_domains` with explicit grants
- Role-based access per project
- Admin can grant/revoke from a dashboard in real-time

### 4. Real-Time Usage Dashboard

Convex subscriptions give live-updating views for free:

- Credits remaining (updates instantly on deduction)
- Active scans per user
- Usage trends (queries over the ledger)

### 5. Rate Limiting & Quotas

```
quotas: {
  userId, dailyScanLimit, concurrentScanLimit, currentDailyUsage
}
```

- Per-user rate limits beyond just credits
- Convex cron jobs to reset daily counters

### 6. Audit Log

```
auditLog: {
  userId, action, resource, metadata, timestamp
}
```

- Track all significant actions (login, scan started, project created, settings changed)
- Queryable from admin UI

## System Boundaries

| System | Keeps | Why |
|--------|-------|-----|
| **WorkOS** | Authentication (login/SSO/session) | Already integrated, good at auth |
| **Stripe** | Payment processing, checkout, invoices | Already integrated, PCI compliant |
| **Convex** | User state, credits ledger, access control, usage tracking | Real-time, transactional, queryable |
| **Go backend** | Scan execution, findings, HTTP records | Core scanner logic |

## Integration Flow

### Login Flow

1. User authenticates via WorkOS (unchanged)
2. On successful login, Next.js middleware upserts user in Convex (`users` table)
3. Convex returns user status — if `suspended` or `pending`, block access
4. Update `lastLoginAt` in Convex

### Credit Purchase Flow

1. User initiates purchase via Stripe checkout (unchanged)
2. Stripe webhook fires `checkout.session.completed`
3. Webhook handler writes to Convex `creditLedger` with `reason: "purchase"` and positive `amount`
4. User record's cached balance updates reactively

### Credit Deduction Flow

1. Proxy middleware intercepts scan-triggering request
2. Calls Convex mutation: `deductCredits(userId, cost, endpoint)`
3. Mutation checks balance, deducts atomically, appends ledger entry
4. Returns success/failure — proxy returns 402 on insufficient credits
5. Forwards request to Go backend on success

### Project Access Flow

1. Admin grants access via UI → Convex mutation adds `projectAccess` row
2. `ProjectContext` queries Convex for user's accessible projects (replaces `allowed_emails` filtering)
3. Revoking access removes the row — takes effect immediately via Convex subscription

## Key Files to Modify

- `src/app/api/proxy/[...path]/route.cloud.ts` — Replace Stripe credit checks with Convex mutations
- `src/app/api/billing/webhook/route.ts` — Write to Convex ledger instead of Stripe metadata
- `src/contexts/ProjectContext.tsx` — Query Convex for project access instead of email filtering
- `src/middleware.cloud.ts` — Add Convex user upsert/status check on login
- `src/api/hooks.ts` — Replace `useCredits()` with Convex subscription
- `src/lib/billing.ts` — Remove Stripe metadata credit functions, add Convex client calls
- `src/app/(app)/settings/` — Add admin user management UI
