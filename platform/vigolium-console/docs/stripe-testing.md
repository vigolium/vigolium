# Stripe Billing — Testing & Production Guide

## Overview

Vigolium Console uses a credit-based billing system powered by Stripe. Users purchase credit packages via Stripe Checkout, and credits are deducted when triggering scan endpoints through the API proxy.

### Credit Packages

| Credits | Price |
|---------|-------|
| 100     | $10   |
| 500     | $40   |
| 1,000   | $70   |

### Scan Costs

| Endpoint                  | Credits | Label                |
|---------------------------|---------|----------------------|
| `/api/scan-url`           | 1       | URL Scan             |
| `/api/scan-request`       | 1       | Request Scan         |
| `/api/scans/run`          | 5       | Full Scan            |
| `/api/scan-all-records`   | 10      | Scan All Records     |
| `/api/scan-records`       | 2       | Scan Selected Records|
| `/api/agent/run/query`    | 2       | Agent Query          |
| `/api/agent/run/autopilot`| 10      | Agent Autopilot      |
| `/api/agent/run/pipeline` | 15      | Agent Pipeline       |
| `/api/agent/run/swarm`    | 20      | Agent Swarm          |

---

## Local Development (No Stripe)

For local development, you can skip billing entirely:

```bash
bun run dev:noauth
# or set VIGOLIUM_SKIP_AUTH=true in .env
```

In this mode:
- Credits are hardcoded to 999,999 (unlimited)
- All billing API routes return stubs (checkout and portal return 400 "Billing disabled in dev mode")
- The proxy never blocks scans for insufficient credits

---

## Testing with Stripe CLI

### 1. Install Stripe CLI

```bash
# macOS
brew install stripe/stripe-cli/stripe

# Or download from https://stripe.com/docs/stripe-cli
```

### 2. Login to Your Stripe Test Account

```bash
stripe login
```

This opens a browser for authentication. Make sure you are on your **test mode** dashboard (toggle in the top-right of Stripe Dashboard).

### 3. Get Your Test API Keys

From [Stripe Dashboard → Developers → API Keys](https://dashboard.stripe.com/test/apikeys):

- **Secret key**: starts with `sk_test_...`
- **Publishable key**: starts with `pk_test_...` (not needed for this app)

Add the secret key to your `.env`:

```
STRIPE_SECRET_KEY=sk_test_...
```

### 4. Forward Webhooks to Localhost

The webhook endpoint is `POST /api/billing/webhook`. Start the Stripe CLI listener:

```bash
stripe listen --forward-to http://localhost:5002/api/billing/webhook
```

The CLI prints a webhook signing secret:

```
> Ready! Your webhook signing secret is whsec_... (^C to quit)
```

Copy that value into `.env`:

```
STRIPE_WEBHOOK_SECRET=whsec_...
```

**Important**: The `whsec_...` from `stripe listen` changes every time you restart the CLI. Update `.env` and restart the dev server if you restart the listener.

### 5. Start the Dev Server (with Auth)

```bash
bun run dev
```

You need WorkOS configured as well for authentication. If you only want to test Stripe in isolation, you can trigger the checkout flow via curl (see "Manual Testing" below).

### 6. Test Credit Cards

Stripe provides test card numbers. **These only work with `sk_test_` keys.**

#### Successful Payments

| Card Number          | Expiry  | CVC  | Result              |
|----------------------|---------|------|---------------------|
| `4242 4242 4242 4242`| Any future date | Any 3 digits | Success             |
| `5555 5555 5555 4444`| Any future date | Any 3 digits | Success (Mastercard)|
| `3782 822463 10005`  | Any future date | Any 4 digits | Success (Amex)      |

#### Declined / Error Cards

| Card Number          | Result                        |
|----------------------|-------------------------------|
| `4000 0000 0000 0002`| Card declined                 |
| `4000 0000 0000 9995`| Insufficient funds            |
| `4000 0000 0000 0069`| Expired card                  |
| `4000 0000 0000 0127`| Incorrect CVC                 |
| `4000 0025 0000 3155`| Requires 3D Secure authentication |

Use **any future expiry** (e.g., `12/34`) and **any CVC** (e.g., `123`).

Full list: https://docs.stripe.com/testing#cards

### 7. End-to-End Testing Flow

1. **Start webhook listener**: `stripe listen --forward-to http://localhost:5002/api/billing/webhook`
2. **Start dev server**: `bun run dev`
3. **Log in** to the console via WorkOS
4. **Navigate to `/billing`** — you should see your current credit balance (0 for new users)
5. **Click "Buy Credits"** — choose a package (100, 500, or 1000 credits)
6. **Stripe Checkout opens** — enter test card `4242 4242 4242 4242`, any future expiry, any CVC
7. **Complete payment** — you are redirected back to `/billing?checkout=success`
8. **Webhook fires** — the `stripe listen` terminal shows the `checkout.session.completed` event
9. **Credits appear** — refresh `/billing` to see updated balance
10. **Run a scan** — trigger any scan endpoint; credits are deducted automatically

### 8. Manual Testing via CLI

You can trigger Stripe events manually without going through the UI:

```bash
# Trigger a checkout.session.completed event
stripe trigger checkout.session.completed
```

Or test specific webhook events:

```bash
# List available trigger events
stripe trigger --list

# Useful events for this app
stripe trigger checkout.session.completed
stripe trigger customer.created
stripe trigger payment_intent.succeeded
```

### 9. Verify Webhook Delivery

Check webhook delivery logs:

```bash
# List recent webhook events
stripe events list --limit 5

# View a specific event
stripe events retrieve evt_...
```

In the `stripe listen` terminal, you should see:

```
2026-03-23 10:00:00   --> checkout.session.completed [evt_...]
2026-03-23 10:00:00  <--  [200] POST http://localhost:5002/api/billing/webhook
```

### 10. Inspect Customer & Credits

```bash
# List customers
stripe customers list --limit 5

# View a specific customer's metadata (where credits are stored)
stripe customers retrieve cus_... --expand metadata
```

Credits are stored in `customer.metadata.credits`. You can manually set credits for testing:

```bash
stripe customers update cus_... --metadata[credits]=500
```

---

## Production Deployment

### Key Differences from Test Mode

| Aspect | Test Mode | Production |
|--------|-----------|------------|
| API Key | `sk_test_...` | `sk_live_...` |
| Cards | Test cards only | Real cards |
| Webhooks | `stripe listen` (CLI) | Configured in Dashboard |
| Money | No real charges | Real money |
| Webhook Secret | From `stripe listen` | From Dashboard endpoint config |

### Production Setup Checklist

1. **Switch to live API key**: Replace `sk_test_...` with `sk_live_...` in your environment variables. **Never commit live keys to source control.**

2. **Configure webhook endpoint in Stripe Dashboard**:
   - Go to [Developers → Webhooks](https://dashboard.stripe.com/webhooks)
   - Click "Add endpoint"
   - URL: `https://your-domain.com/api/billing/webhook`
   - Events to listen for: `checkout.session.completed`
   - Copy the signing secret (`whsec_...`) to `STRIPE_WEBHOOK_SECRET`

3. **Configure Stripe Customer Portal** (for the "Manage Billing" button):
   - Go to [Settings → Billing → Customer Portal](https://dashboard.stripe.com/settings/billing/portal)
   - Enable the portal and configure what customers can do (view invoices, update payment methods, etc.)

4. **Environment variables for production**:
   ```
   STRIPE_SECRET_KEY=sk_live_...
   STRIPE_WEBHOOK_SECRET=whsec_...   # from Dashboard, NOT from stripe listen
   VIGOLIUM_SKIP_AUTH=false
   ```

5. **Do NOT use `stripe listen` in production** — it is a development tool only. Webhooks are delivered directly by Stripe to your configured endpoint URL.

6. **Credit cost overrides** (optional): Set `VIGOLIUM_CREDIT_COSTS` env var with a JSON object to override default costs:
   ```
   VIGOLIUM_CREDIT_COSTS={"\/api\/scan-url":2,"\/api\/agent\/run\/pipeline":25}
   ```

### Production Monitoring

- **Stripe Dashboard**: Monitor payments, failed charges, and disputes at https://dashboard.stripe.com
- **Webhook failures**: Stripe retries failed webhook deliveries for up to 3 days. Check [Developers → Webhooks → endpoint → Attempted deliveries] for failures
- **Credit balance**: Credits are stored as Stripe customer metadata (`customer.metadata.credits`). You can view and edit this in the Dashboard under each customer's details

### Common Production Issues

- **308 redirect on webhooks**: If `trailingSlash: true` is set in `next.config.ts` without `skipTrailingSlashRedirect: true`, Next.js will 308-redirect POST requests from `/api/billing/webhook` to `/api/billing/webhook/`. This drops the request body and `stripe-signature` header, so the webhook silently fails. The fix is already applied (`skipTrailingSlashRedirect: true`), but if you ever see `[308]` responses in `stripe listen` output, this is the cause. As a fallback, you can also use the trailing-slash URL: `stripe listen --forward-to http://localhost:5002/api/billing/webhook/`
- **Webhook signature mismatch**: Make sure `STRIPE_WEBHOOK_SECRET` matches the signing secret from your Dashboard webhook endpoint (not from `stripe listen`)
- **Stale credits after payment**: Usually means the webhook didn't fire or failed. Check webhook delivery logs in Stripe Dashboard
- **402 on scans**: User has insufficient credits. They need to purchase more from `/billing`
