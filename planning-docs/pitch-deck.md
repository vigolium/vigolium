# Vigolium Pitch Deck — Outline & Content

Audience-aware pitch deck for introducing Vigolium. Default flow is written for a **non-technical** audience; a technical appendix slide is included for when a technical person in the room asks for detail.

---

## Slide 1 — Title / Hook

> **Vigolium**
> *The first web security scanner that thinks.*
>
> It reads your code, plans its own attacks, and finds the bugs hackers would find — automatically.

**One-liner for the room:** "Imagine hiring a senior security expert who never sleeps, reads every line of your app, and tests it the way a real attacker would — at machine speed. That's Vigolium."

---

## Slide 2 — The Problem

Every company with a website or app faces the same question: **"Is this safe to ship?"**

Today, the answers are all unsatisfying:

- **Hire a pentester** — Expensive ($20k–$100k per engagement), slow (weeks), and a snapshot in time. The moment your team ships new code, the report is out of date.
- **Buy a traditional scanner** — These tools run through a checklist of *known* problems. They're fast, but they miss anything clever, custom, or specific to your business logic. High noise, low trust.
- **Use a code-analysis tool** — These read your source code but never actually test the running app. They generate mountains of warnings, most of which aren't real — so developers stop reading them.

**The gap:** No tool is both smart *and* fast. You get human-level thinking (slow, costly) or machine-level speed (shallow, noisy). Never both.

---

## Slide 3 — What Vigolium Is

Vigolium is a **web security scanner that combines AI reasoning with high-speed automated testing.**

Three things make it different:

1. **It reads your source code** — and uses that understanding to test your app the way someone who built it would.
2. **It plans its own attacks** — AI agents decide what to test, write custom probes on the fly, and review the results.
3. **It runs at machine speed** — 200+ built-in security checks run in parallel, covering everything from common bugs to modern framework-specific flaws.

One tool. One command. The depth of a human expert, the speed of a machine.

---

## Slide 4 — How It's Different (Plain English)

### 1. It understands your app, not just its surface
Traditional scanners poke at a website from the outside like a stranger rattling doorknobs. Vigolium can *read the blueprints* — your actual source code — and go straight to the risky areas.

### 2. It thinks, then acts
Most scanners run a fixed list of checks. Vigolium's AI agents look at your app, decide what's worth testing, and **write custom tests on the fly** for things no generic scanner could catch.

### 3. It filters its own noise
AI reviews every finding and throws out the false alarms before a human ever sees them. Your team only reviews real issues.

### 4. It speaks every format
Got an API spec? A recorded browser session? A cURL command? A Postman collection? Vigolium takes them all as input — no manual setup.

### 5. It's built for teams, not just individuals
Runs as a command-line tool for a solo researcher, or as a server with a web dashboard for a whole security team, with project separation so different apps stay organized.

### 6. Bring your own AI
Works with Claude, OpenAI, OpenCode, or any custom AI backend — **you bring your own API key / LLM token.** No lock-in, no surprise bills from us for AI usage, no sensitive data sent through a middleman.

---

## Slide 5 — Competitive Landscape (for the general audience)

The security-testing market today breaks into three camps. Vigolium is the first tool that sits in all three.

| What you want | Manual pentest tools | Automated scanners | Code-review tools | **Vigolium** |
|---|:-:|:-:|:-:|:-:|
| Tests the live app | ✅ | ✅ | ❌ | ✅ |
| Reads your source code | ❌ | ❌ | ✅ | ✅ |
| AI plans the attacks | ❌ | ❌ | ❌ | ✅ |
| AI filters false alarms | ❌ | ❌ | ❌ | ✅ |
| Covers modern web apps (React, Next.js, mobile APIs) | ⚠️ | ⚠️ | ⚠️ | ✅ |
| Fast enough to run on every code change | ❌ | ✅ | ✅ | ✅ |
| Works without a human driver | ❌ | ✅ | ✅ | ✅ |
| You choose the AI provider | N/A | ❌ | ❌ | ✅ |

**The one-sentence pitch:** Nothing else on the market reads your code, plans its own attacks, and validates them against your live app — in a single command.

---

## Slide 5b — Competitive Landscape (technical appendix)

For folks who know the space, here's the head-to-head against the specific tools they already use:

| Capability | Burp Pro | OWASP ZAP | Nuclei | Acunetix | **Vigolium** |
|---|:-:|:-:|:-:|:-:|:-:|
| Active scan modules | ~100 | ~60 | templates only | ~150 | **127 (+ 83 passive)** |
| AI-driven payload generation | ❌ | ❌ | ❌ | ⚠️ limited | ✅ |
| Source-code awareness | ❌ | ❌ | ❌ | ❌ | ✅ |
| Agentic autopilot | ❌ | ❌ | ❌ | ❌ | ✅ |
| Custom JS extensions at runtime | ⚠️ | ⚠️ | ❌ | ❌ | ✅ |
| OAST / blind vulns | ⚠️ add-on | ❌ | ⚠️ | ✅ | ✅ |
| Multi-project REST API | ❌ | ⚠️ | ❌ | ✅ | ✅ |
| Pricing model | $500/user/yr | Free | Free | $$$$ enterprise | TBD |
| Headless / CI-friendly | ⚠️ | ✅ | ✅ | ⚠️ | ✅ |

**Brief gloss for non-technical viewers if this slide comes up:** Burp Suite and ZAP are the industry-standard manual tools; Nuclei is the popular open-source template scanner; Acunetix is the leading enterprise scanner. Vigolium matches or beats each on their home turf — and does things none of them do.

**How to use the two slides:**
- **Default flow:** show the plain-English version (Slide 5) and move on.
- **If a technical person asks "how do you compare to Burp / Nuclei / Acunetix?":** flip to Slide 5b.
- **In the written/shared deck:** put 5b in an appendix so it's there for later readers but doesn't interrupt the narrative.

---

## Slide 6 — How It Works (the simple version)

```
  Your app  +  Your source code
       ↓
  AI reads the code and maps the risky areas
       ↓
  AI plans the attack and writes custom tests
       ↓
  200+ automated checks run in parallel
       ↓
  AI reviews the findings and removes false alarms
       ↓
  Clean report  →  dashboard, PDF, or your CI pipeline
```

All of this happens automatically, in minutes, from one command.

---

## Slide 7 — Coverage Breadth

Vigolium checks for the full range of modern web security problems:

- **Data leaks** — sensitive info exposed in responses, headers, or error pages
- **Broken access controls** — users able to see or change data they shouldn't
- **Injection attacks** — the #1 cause of data breaches (SQL, XSS, command injection, and more)
- **Authentication flaws** — weak logins, broken sessions, token issues
- **Cloud & infrastructure exposure** — misconfigured storage buckets, leaked credentials
- **Framework-specific bugs** — tailored checks for the most popular tech stacks (Next.js, Django, Rails, Spring, Laravel, FastAPI, and more)
- **"Blind" vulnerabilities** — subtle bugs that don't show any obvious symptom, caught via an advanced callback technique

Covers the OWASP Top 10 (the industry-standard list of the most dangerous web bugs) and far beyond.

---

## Slide 8 — Validation

Vigolium is continuously tested against:
- **Industry-standard vulnerable apps** used to benchmark every security tool (DVWA, OWASP Juice Shop, VAmPI, crAPI)
- **Public test sites** run by competing vendors
- **Real-world bug bounty programs** — finding actual, previously-unknown vulnerabilities in production applications

If the industry has a benchmark for it, Vigolium is being measured against it.

---

## Slide 9 — Who It's For

- **Security teams** at companies with many apps to cover — one tool, dashboard, and API across the whole portfolio
- **Professional pentesters & bug bounty hunters** — a force multiplier that does the grunt work and surfaces the interesting findings
- **Engineering teams** — plug it into CI/CD so every code change gets tested automatically before shipping
- **Security researchers** — extend it with custom scripts, or let the AI write the scripts for you

---

## Slide 10 — Traction & Roadmap

- **200+** built-in security checks shipping today
- **Bring-your-own-LLM** — works with Claude, OpenAI, OpenCode, or any custom AI backend using your own API key
- **7** input formats supported out of the box
- **Web dashboard** shipping for team workflows
- *(Add: user count, scan count, GitHub stars, design partners, notable bugs found)*

---

## Slide 11 — The Ask / Close

- **For investors:** AI-native security testing is a new category forming right now. Vigolium is the reference implementation.
- **For enterprise buyers:** Replace three tools (pentest prep, automated scanner, code review) with one that your team will actually use.
- **For the community:** Open, extensible, and doesn't lock you into any single AI vendor.

---

## Suggested flow

11 slides, ~12 minutes spoken, 3 minutes live demo — point Vigolium at a deliberately-broken sample app, show it read the code, plan the attack, find real bugs, and produce a clean report. That's the "nothing else does this" moment.
