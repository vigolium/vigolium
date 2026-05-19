# Getting Started with Codex OAuth

If you already use the official OpenAI **Codex CLI** for coding, vigolium reuses the same `~/.codex/auth.json` — no separate login, no API key, refresh handled automatically.

## 1. Verify codex works

```bash
codex exec 'what model are you running'
```

If that prints a model name, you're good. If not, fix codex first (re-run `codex login`); vigolium consumes the file it produces.

## 2. Point vigolium at codex

```bash
vigolium config set agent.olium.provider openai-codex-oauth
vigolium config set agent.olium.oauth_cred_path ~/.codex/auth.json
vigolium config set agent.olium.model gpt-5.5
```

These are the defaults, so you can skip them — but setting them explicitly pins the choice in `~/.vigolium/vigolium-configs.yaml` so a future profile or env var can't silently override.

## 3. Test it

```bash
vigolium ol -p 'what model are you running'
```

Same answer as the codex check above means everything is wired. From here, jump to [`autopilot.md`](autopilot.md) or [`olium-agent.md`](olium-agent.md).
