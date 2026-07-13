# access-lab — authenticated IDOR / broken-access-control demo

A tiny, deliberately vulnerable app (stdlib Go, no deps) used by the
durable-autopilot agent demo. It exists to exercise the bug classes an
**unauthenticated native scan cannot find on its own**: the agent must read
natural-language credentials from its prompt, log in, hold the session, and
reason about per-object / per-role authorization.

**Do not deploy this. It is intentionally insecure.**

## Accounts

| username | password | id  | role  | notes                        |
|----------|----------|-----|-------|------------------------------|
| wiener   | peter    | 1   | user  | the low-privilege attacker   |
| carlos   | hunter2  | 2   | user  | a victim account             |
| admin    | admin123 | 100 | admin |                              |

## Ground-truth vulnerabilities

| id | class | request | why it's a bug |
|----|-------|---------|----------------|
| V1 | IDOR / BOLA (horizontal) | `GET /api/users/{id}` | authenticated, but no ownership check — wiener reads carlos's & admin's PII |
| V2 | IDOR / BOLA (horizontal) | `GET /api/orders/{id}` | no ownership check — wiener reads any order incl. its `secret_note` |
| V3 | Broken access control (vertical) | `GET /admin/dashboard` | authenticated but not role-gated — a normal user reaches the admin dashboard + `FLAG{...}` |
| V4 | Broken access control (vertical) | `POST /admin/promote?user={id}` | state-changing admin action with no role check — privilege escalation |
| V5 | DOM-based XSS (browser-only) | `GET /welcome?name=<payload>` | the `name` value is **never in the server response** — an inline script reads `location.search` and writes it to `innerHTML`. A reflection scanner sees nothing; only a browser fires it. |
| V6 | Stored XSS (multi-step + browser) | `POST /api/reviews` → `GET /product` | authenticate, store a comment, then the product page fetches reviews and injects each `comment` via `innerHTML` — executes in any viewer's browser. Needs login **and** the two-step post-then-render **and** a real browser. |
| V7 | Mass assignment (multi-step logic) | `PATCH /api/me {"credits":999999}` | arbitrary body fields are merged into your own record — set your own `credits` (or `role`). A native scan won't attempt this shape. |

Login: `POST /login` (form or JSON `{"username","password"}`) sets a `session`
cookie. All `/api/*`, `/admin/*` routes require the cookie but skip the
authorization that should follow. V5/V6 require a **browser** to confirm
(`--browser`, agent-browser); V6 and V7 require **multiple sequential steps**.

## Run

```bash
make access-lab-up     # docker compose up (:9899)
make access-lab-down
```

Or standalone (no Docker): `go run .` from this directory (listens on :9899;
override with `ACCESS_LAB_ADDR`).

The end-to-end agent demo that logs in and hunts these bugs lives at
`scripts/e2e-autopilot-access.sh` (`make test-e2e-autopilot-access`).
