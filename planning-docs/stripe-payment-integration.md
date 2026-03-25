# Stripe Payment Integration — Credit-Based Billing

## Overview

Add a credit-based payment system to Vigolium SaaS using Stripe. Users purchase credit packs, and credits are deducted per scan. All billing logic lives in the Next.js dashboard (`platform/vigolium-dashboard/`); the Go scanner remains stateless and billing-unaware.

## Prerequisites

- **WorkOS auth must be implemented first** (see `docs/planning/auth-with-workos-integration.md`). Stripe integration depends on having authenticated users with stable IDs (WorkOS `user.id`).
- **Dashboard must be server-rendered** — the current `output: 'export'` static build cannot handle webhooks, server actions, or secret keys. The WorkOS migration already requires this change (remove `output: 'export'` from `next.config.ts` in production, deploy to Vercel/Node server instead of static hosting).

## Architecture

```
User Browser
  │
  ▼
Next.js Dashboard (server-rendered)
  ├── WorkOS Auth (session, JWT)
  ├── Stripe Checkout (redirect to hosted payment page)
  ├── Stripe Webhook handler (POST /api/stripe/webhook)
  ├── Credit balance DB (Postgres via Prisma/Drizzle)
  ├── Server Actions: check balance, deduct credits
  └── Calls Go scanner API only after credit check passes
        │
        ▼
Go Scanner Server (stateless)
  ├── Verifies JWT from WorkOS (identity only)
  ├── Executes scans
  ├── Stores findings, http_records
  └── Serves scan data via REST API
       (zero knowledge of billing)
```

### Why billing lives in Next.js, not Go

1. **Separation of concerns** — The Go binary is a scanner. It deploys to customer-premise, CI runners, and environments where Stripe keys should not exist.
2. **The dashboard is the SaaS control plane** — It already handles auth (WorkOS), project selection, and will handle teams/orgs. Billing is a natural extension.
3. **Server Actions** — Next.js server actions provide a clean way to handle Stripe operations without building a separate API. Secret keys stay server-side.
4. **Single database** — The dashboard needs its own DB anyway for SaaS-level data (users, teams, plans). Credits belong in the same store.

### How the Go scanner stays billing-unaware

The dashboard acts as a **gatekeeper**:

1. User clicks "Start Scan" in the dashboard UI
2. Dashboard server action: verify auth → check credits → deduct 1 credit → call Go scanner API
3. Go scanner receives the request with a valid JWT, runs the scan, returns results
4. If the user has no credits, the dashboard rejects the request before it ever hits Go

For CLI usage: the CLI calls a dashboard API endpoint (`POST /api/credits/reserve`) to reserve a credit before starting a scan. This can be added later.

## Stripe Account Setup

1. Register at https://dashboard.stripe.com/register
2. Start in **test mode** (use `pk_test_*` / `sk_test_*` keys for development)
3. Create **Products** in the Stripe Dashboard:
   - "Starter Pack" — 50 credits, $19 (one-time)
   - "Pro Pack" — 200 credits, $49 (one-time)
   - "Team Pack" — 1000 credits, $199 (one-time)
   - Adjust names/amounts as needed. These are one-time payments, not subscriptions.
4. Note the **Price IDs** (`price_...`) for each product — used in checkout session creation
5. Set up webhook endpoint: **Developers → Webhooks → Add endpoint**
   - URL: `https://your-dashboard-domain.com/api/stripe/webhook`
   - Events: `checkout.session.completed`
   - Note the **Webhook Signing Secret** (`whsec_...`)

## Database Schema

Add a database to the Next.js dashboard. Use **Prisma** (most mature Next.js ORM) with **PostgreSQL** (Vercel Postgres, Supabase, Neon, or self-hosted).

### Tables

```prisma
// prisma/schema.prisma

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

generator client {
  provider = "prisma-client-js"
}

// Users synced from WorkOS — minimal local record
model User {
  id              String   @id              // WorkOS user ID (from JWT sub claim)
  email           String   @unique
  stripeCustomerId String? @unique @map("stripe_customer_id")
  createdAt       DateTime @default(now())  @map("created_at")
  updatedAt       DateTime @updatedAt       @map("updated_at")

  creditBalance   CreditBalance?
  transactions    CreditTransaction[]

  @@map("users")
}

// Current credit balance (denormalized for fast reads)
model CreditBalance {
  userId    String   @id @map("user_id")
  balance   Int      @default(0)
  updatedAt DateTime @updatedAt @map("updated_at")

  user User @relation(fields: [userId], references: [id])

  @@map("credit_balances")
}

// Audit trail of all credit changes
model CreditTransaction {
  id              String   @id @default(cuid())
  userId          String   @map("user_id")
  amount          Int                          // +N for purchase, -1 for scan
  reason          String                       // "purchase", "scan", "refund", "bonus"
  stripeSessionId String?  @map("stripe_session_id")
  scanUuid        String?  @map("scan_uuid")  // links to Go scanner scan
  createdAt       DateTime @default(now())     @map("created_at")

  user User @relation(fields: [userId], references: [id])

  @@index([userId, createdAt])
  @@map("credit_transactions")
}
```

**Why both `credit_balances` and `credit_transactions`?**
- `credit_balances` — Fast O(1) balance lookups before every scan. Single row per user.
- `credit_transactions` — Audit trail. Answers "when did they buy?", "which scans consumed credits?", "why did balance change?". Essential for support and billing disputes.

## Next.js Implementation

### 1. Install dependencies

```bash
cd platform/vigolium-dashboard
bun add stripe @stripe/stripe-js prisma @prisma/client
bun add -d prisma
bunx prisma init
```

### 2. Environment variables

```env
# .env.local (never commit)
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_test_...
DATABASE_URL=postgresql://...
```

### 3. Stripe server client

Create `src/lib/stripe.ts`:

```typescript
import Stripe from "stripe";

export const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: "2025-01-27.acacia",  // pin to latest stable
});
```

### 4. Checkout session — Server Action

Create `src/app/actions/stripe.ts`:

```typescript
"use server";

import { withAuth } from "@workos-inc/authkit-nextjs";
import { stripe } from "@/lib/stripe";
import { prisma } from "@/lib/prisma";
import { redirect } from "next/navigation";

export async function createCheckoutSession(priceId: string) {
  const { user } = await withAuth({ ensureSignedIn: true });

  // Find or create Stripe customer
  let dbUser = await prisma.user.findUnique({ where: { id: user.id } });
  if (!dbUser) {
    dbUser = await prisma.user.create({
      data: { id: user.id, email: user.email },
    });
  }

  let stripeCustomerId = dbUser.stripeCustomerId;
  if (!stripeCustomerId) {
    const customer = await stripe.customers.create({
      email: user.email,
      metadata: { workos_user_id: user.id },
    });
    stripeCustomerId = customer.id;
    await prisma.user.update({
      where: { id: user.id },
      data: { stripeCustomerId },
    });
  }

  const session = await stripe.checkout.sessions.create({
    customer: stripeCustomerId,
    line_items: [{ price: priceId, quantity: 1 }],
    mode: "payment",
    success_url: `${process.env.NEXT_PUBLIC_APP_URL}/billing?success=true`,
    cancel_url: `${process.env.NEXT_PUBLIC_APP_URL}/billing?canceled=true`,
    metadata: { workos_user_id: user.id },
  });

  redirect(session.url!);
}
```

### 5. Webhook handler — Route Handler

Create `src/app/api/stripe/webhook/route.ts`:

```typescript
import { NextRequest, NextResponse } from "next/server";
import { stripe } from "@/lib/stripe";
import { prisma } from "@/lib/prisma";
import Stripe from "stripe";

// Stripe price ID → credit amount mapping
const CREDIT_PACKS: Record<string, number> = {
  "price_starter_xxx": 50,
  "price_pro_xxx": 200,
  "price_team_xxx": 1000,
};

export async function POST(req: NextRequest) {
  const body = await req.text();
  const sig = req.headers.get("stripe-signature")!;

  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(
      body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET!
    );
  } catch {
    return NextResponse.json({ error: "Invalid signature" }, { status: 400 });
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data.object as Stripe.Checkout.Session;
    const userId = session.metadata?.workos_user_id;
    if (!userId) return NextResponse.json({ error: "No user ID" }, { status: 400 });

    // Retrieve line items to determine which pack was purchased
    const lineItems = await stripe.checkout.sessions.listLineItems(session.id);
    const priceId = lineItems.data[0]?.price?.id;
    const credits = priceId ? CREDIT_PACKS[priceId] ?? 0 : 0;

    if (credits > 0) {
      await prisma.$transaction([
        // Upsert balance
        prisma.creditBalance.upsert({
          where: { userId },
          create: { userId, balance: credits },
          update: { balance: { increment: credits } },
        }),
        // Record transaction
        prisma.creditTransaction.create({
          data: {
            userId,
            amount: credits,
            reason: "purchase",
            stripeSessionId: session.id,
          },
        }),
      ]);
    }
  }

  return NextResponse.json({ received: true });
}
```

### 6. Credit check — Server Action

Create `src/app/actions/credits.ts`:

```typescript
"use server";

import { withAuth } from "@workos-inc/authkit-nextjs";
import { prisma } from "@/lib/prisma";

export async function getBalance(): Promise<number> {
  const { user } = await withAuth({ ensureSignedIn: true });
  const balance = await prisma.creditBalance.findUnique({
    where: { userId: user.id },
  });
  return balance?.balance ?? 0;
}

export async function deductCredit(scanUuid: string): Promise<boolean> {
  const { user } = await withAuth({ ensureSignedIn: true });

  try {
    // Atomic: only deduct if balance >= 1 (prevents going negative)
    await prisma.$transaction(async (tx) => {
      const updated = await tx.$executeRaw`
        UPDATE credit_balances
        SET balance = balance - 1, updated_at = NOW()
        WHERE user_id = ${user.id} AND balance >= 1
      `;
      if (updated === 0) throw new Error("Insufficient credits");

      await tx.creditTransaction.create({
        data: {
          userId: user.id,
          amount: -1,
          reason: "scan",
          scanUuid,
        },
      });
    });
    return true;
  } catch {
    return false;
  }
}
```

### 7. Scan initiation with credit check

Modify the scan trigger flow in the dashboard. Currently scans are initiated via `apiPost("/api/scan", ...)` directly from the client. With credits, the flow becomes:

```typescript
// src/app/actions/scan.ts
"use server";

import { withAuth } from "@workos-inc/authkit-nextjs";
import { deductCredit } from "./credits";

export async function startScan(scanConfig: ScanRequest) {
  const { accessToken } = await withAuth({ ensureSignedIn: true });

  // 1. Deduct credit (atomic, fails if insufficient)
  const scanUuid = crypto.randomUUID();
  const ok = await deductCredit(scanUuid);
  if (!ok) {
    return { error: "Insufficient credits. Please purchase more." };
  }

  // 2. Forward to Go scanner API
  const res = await fetch(`${process.env.VIGOLIUM_API_URL}/api/scan`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(scanConfig),
  });

  if (!res.ok) {
    // Refund the credit if scan failed to start
    // (implement refundCredit similarly to deductCredit)
    return { error: "Failed to start scan" };
  }

  return { success: true, scanUuid };
}
```

## Frontend UI Components

### Billing page (`src/app/billing/page.tsx`)

- **Current balance** — Prominent display of remaining credits
- **Purchase packs** — Cards for each credit pack with "Buy" buttons that call `createCheckoutSession(priceId)`
- **Transaction history** — Table of recent credit changes (purchases, scans, refunds)
- **Manage billing** — Link to Stripe Customer Portal for payment methods and invoices

### Credit balance in header/nav

- Show remaining credits in the top nav bar
- Warning indicator when balance is low (< 5 credits)

### Stripe Customer Portal

For managing payment methods and viewing invoices, redirect to Stripe's hosted portal instead of building custom UI:

```typescript
"use server";

export async function createPortalSession() {
  const { user } = await withAuth({ ensureSignedIn: true });
  const dbUser = await prisma.user.findUnique({ where: { id: user.id } });

  const session = await stripe.billingPortal.sessions.create({
    customer: dbUser!.stripeCustomerId!,
    return_url: `${process.env.NEXT_PUBLIC_APP_URL}/billing`,
  });

  redirect(session.url);
}
```

Enable the Customer Portal in Stripe Dashboard → **Settings → Billing → Customer Portal**.

## Deployment Considerations

### Next.js must be server-rendered

Remove the static export for production. Update `next.config.ts`:

```typescript
const nextConfig: NextConfig = {
  // Remove: output: 'export'
  // Deploy to Vercel, Docker, or Node.js server
  trailingSlash: true,
  images: {
    unoptimized: true,
  },
};
```

This is already required for WorkOS auth (middleware, server components, server actions).

### Hosting options

- **Vercel** — Easiest. Native Next.js support, serverless functions for server actions and webhooks, edge middleware for auth.
- **Docker** — `next start` in a container. Need to expose the webhook endpoint publicly.
- **Self-hosted Node** — Same as Docker without the container.

### Stripe webhook in development

Use the Stripe CLI to forward webhooks to localhost:

```bash
stripe listen --forward-to localhost:3000/api/stripe/webhook
```

This prints a `whsec_...` key to use as `STRIPE_WEBHOOK_SECRET` in `.env.local`.

## Implementation Order

1. **WorkOS auth** — Implement first per `auth-with-workos-integration.md`
2. **Remove static export** — Switch to server-rendered Next.js, deploy accordingly
3. **Add Prisma + database** — Set up PostgreSQL, create schema, run migrations
4. **Stripe account** — Register, create products/prices, get API keys
5. **Checkout flow** — Server action to create session, redirect to Stripe
6. **Webhook handler** — Receive `checkout.session.completed`, add credits
7. **Credit check** — Server action to verify balance before scan
8. **Wire scan flow** — Dashboard deducts credit before calling Go scanner API
9. **Billing UI** — Balance display, purchase page, transaction history
10. **Stripe Customer Portal** — Link for payment method management
11. **Testing** — End-to-end with Stripe test mode, verify credit lifecycle

## Future Enhancements (not in initial scope)

- **Subscription plans** — Monthly credit allowances instead of one-time packs
- **Team credits** — Shared credit pool per WorkOS organization
- **CLI credit check** — `vigolium scan` calls dashboard API to reserve credit before scanning
- **Usage-based pricing** — Different credit costs per scan type (quick=1, full=5, agent=10)
- **Auto-refill** — Automatically purchase more credits when balance drops below threshold
- **Free tier** — N free credits per month for new users
