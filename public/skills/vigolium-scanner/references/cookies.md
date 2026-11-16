# Borrowed browser sessions (`vigolium kit cookies`)

> **Related:** [kit.md](kit.md) for the other `kit` primitives · [recipes.md](recipes.md) for the Playwright recipe · [auth.md](auth.md) when the scan must re-authenticate

Read the cookies — and, with `--with-storage`, the `localStorage` — the
operator's **own** local browser already holds for a domain, so an
authenticated surface can be tested without driving a login first. The output
feeds Playwright (`storageState`), curl (`-b`), a raw `Cookie:` header, or
vigolium's own authenticated phases.

```bash
vigolium kit cookies app.target.example                      # redacted listing
vigolium kit cookies app.target.example -j                   # what is there (values masked under an agent)
vigolium kit cookies target.example --apex \
    --as playwright -o state.json                            # a storageState
vigolium kit cookies app.target.example --with-storage \
    --as playwright -o state.json                            # cookies + storage
vigolium kit cookies app.target.example --as header -o cookie.txt   # a Cookie header, to a file
vigolium kit cookies profiles                                # what profiles exist
vigolium kit cookies doctor                                  # will this work here?
```

**Values are redacted by default, and under a coding agent they stay out of the
transcript.** With a coding-agent variable set (`CLAUDECODE` and the like, or
`VIGOLIUM_REDACT=1`), `-j` masks every cookie and storage value (the envelope
says `redacted: true`) and `--stdout` is refused (exit 2). The values leave
through `--as … -o <file>`: the file is created mode `0600` before any bytes
land — it holds a live session, not a report — and a browser or `curl` loads
it without anyone reading it. Do that. `--reveal` (or `VIGOLIUM_REDACT=0`,
`--no-redact`) prints values on purpose; outside an agent `-j` and `--stdout`
carry them as before.

An `-o` file that already exists is **never replaced by an empty or failed
read**: nothing matched → the file is kept, `output_kept` names it, exit 3; the
keyring refused the key → nothing is written, exit 1 `keyring_denied`. A
first-run notice on stderr says that the OS will ask for approval and that EDR
commonly alerts on a process reading a browser credential store; `--yes` or
`VIGOLIUM_COOKIES_ACK=1` (`1`/`true`/`yes`/`on` — `0`, `false` or a typo is not an acknowledgement)
silences it.

| Flag | Default | Effect |
|------|---------|--------|
| `--scope` | `host` | `host` (what a request to that host carries), `subdomains` (also hosts below it), `apex` (widen to the eTLD+1 first) |
| `--apex` | — | shorthand for `--scope apex` |
| `--browser` | all | `chrome`, `chromium`, `brave`, `edge`, `opera`, `firefox`, `safari` |
| `--profile` | all | by label (`Work`) **or** directory (`Profile 3`) |
| `--user-data-dir` | — | an extra Chromium root: Chrome for Testing, Chrome Beta, a Playwright profile |
| `--name` | all | keep only these cookie names |
| `--as` | — | `playwright`, `playwright-init`, `netscape`, `header`, `json`, `jsonl`; needs `-o` (or `--stdout`, refused under an agent without `--reveal`). Named `--as`, not `--format`: the global `--format` is the report-format flag |
| `--same-site` | — | force `strict`/`lax`/`none` on export (see the SameSite gotcha) |
| `--with-storage` | off | also read each matching origin's `localStorage` + `sessionStorage`; `--as playwright` carries localStorage only, `playwright-init` sessionStorage only, `json`/`jsonl`/`-j` both |
| `--reveal` | off | show values in the listing and in `-j` under an agent; allow `--stdout` under one |
| `--no-prompt` | off | never raise the macOS keychain dialog: a store that needs it fails `keyring_denied` (unattended runs) |
| `--clone-profile <dir>` | — | write a scoped profile clone instead of an export — the only output that carries IndexedDB |
| `--include-expired` | off | keep cookies whose expiry has passed |
| `--require-match` | off | exit **3** when nothing matched |

Scope is **not** a string compare. A `.target.example` cookie serves every host
under the domain; a `target.example` cookie with no leading dot serves that host
alone. `--scope host` returns what a browser would actually send, which is why
it is the default; `--apex` uses the public suffix list, so
`a.b.example.co.uk` widens to `example.co.uk`, never `co.uk`.

`-j` is a read envelope: `items` = the cookies
(`{name, value, domain, path, secure, http_only, same_site, expires, created,
browser, profile, profile_label, store_file}`) plus top-level `domains`,
`scope`, `matched` (the hostnames the scope resolved to), `count`, `stores`
(one `{store, count, problem, detail}` per store consulted), `warnings`, and
`problem`.

With `--with-storage`, top-level `origins` carries
`{origin, local_storage, session_storage, session_namespaces, partitioned,
top_level_site, browser, profile}` and `storage_items` counts the entries;
`unreadable` lists the IndexedDB stores no export can carry. With
`--clone-profile`, `clone` reports the directory, what it holds, and the
rewrites it needed. `--as jsonl` tags every line
with `kind` (`cookie` or `origin`) so one stream carries both.

`expires` is absent for a session cookie and `same_site` is empty whenever the
store did not record the attribute (every Chromium cookie today — see the
gotcha). `created` is absent unless the store holds a real creation time: the
Chromium reader derives it from the SQLite rowid, so an implausible value is
dropped rather than published.

**Read `problem` before trusting an empty result.** Every way this can fail
looks like "that domain has no cookies": the key is fetched lazily per row and
an undecryptable row is skipped. Exit `1` carries the reason as `error.code` —
`keyring_denied` (the OS would not release the key, the prompt went unanswered
for 2 minutes, or `--no-prompt` refused to raise it: approve the prompt in a
desktop session, then retry) or `browser_encryption_unsupported` (Chrome 127+
App-Bound Encryption on Windows: unreadable by any other process — and a clone
copies the same unreadable values, so log in through a driven browser
instead).

## Local storage

`--with-storage` reads the profile's LevelDB store and puts each matching
origin's `localStorage` into the storageState's `origins[]`, so one Playwright
context restores cookies and storage together. The store is **copied** before
it is opened: a running browser holds LevelDB's lock, and a LevelDB open
replays the write-ahead log, so reading the original would mean writing to a
profile the operator is still browsing with.

Two things differ from cookies and will bite otherwise:

- **Isolation is per ORIGIN, not per cookie domain.** A `.target.example`
  cookie reaches every subdomain; `https://app.target.example`'s storage is not
  `https://target.example`'s and they share nothing. `--scope host` therefore
  returns one origin — widen with `--scope subdomains` to collect a site's
  origins, and expect the scheme and port to matter.
- **Partitioned third-party storage is reported but not exported.** Chromium
  keys embedded third-party storage to its top-level site; on a real profile
  about a quarter of the origins are partitioned. A storageState cannot express
  the partition, so those origins are kept out of it (restoring one
  unpartitioned would put another site's view of that origin into the
  first-party bucket) and carried in `-j` instead, flagged `partitioned` with
  their `top_level_site`.

`sessionStorage` is read too, from its own store. It is scoped per **tab**, so
an origin has one namespace per open tab; they are merged and the count is
reported. A storageState has no field for it, so `--as playwright-init` writes a
JS snippet to restore it:

```bash
vigolium kit cookies app.target.example --with-storage --as playwright -o state.json
vigolium kit cookies app.target.example --with-storage --as playwright-init -o session-init.js
```

```js
const ctx = await browser.newContext({ storageState: 'state.json' });
await ctx.addInitScript({ path: 'session-init.js' });
```

`--as netscape` and `--as header` are cookie-only wire formats and warn that the
storage they cannot carry was dropped.

## Profile clone (IndexedDB, and the session that lives there)

IndexedDB is **not** parsed. Its values are Blink structured-clone blobs — a
versioned, engine-internal format with no specification outside Chromium's
source — and a partial parser would return values a caller cannot distinguish
from what the app actually stored. Firebase Auth and several SPA auth libraries
keep the session there, which produces a storageState that restores every cookie
and still lands on a login page.

`--clone-profile` answers it by handing the browser its own files:

```bash
vigolium kit cookies app.target.example --clone-profile ./agent-profile
```

```js
const ctx = await chromium.launchPersistentContext('./agent-profile', { headless: false });
```

The clone is **scoped**: cookie rows deleted, every storage row that is not an
in-scope origin's deleted (metadata and access rows included) and the LevelDB
compacted so the bytes actually leave the files, and only the matching
per-origin IndexedDB directories copied at all. It is built in a `0700`
staging directory beside the destination and renamed into place when done, so
a failed or interrupted clone leaves nothing at the path. A whole Chrome profile is
hundreds of megabytes and every login the operator has; a clone of one site is a
few. `Preferences` is not copied (it carries per-site settings for every site
visited) and neither is `Local State` beyond the encryption key Windows keeps
there. Service Worker and Cache Storage are skipped as caches.

Two rewrites make the clone usable, both reported:

- **Cookie values are written as plaintext**, clearing `encrypted_value`. The
  copied values are sealed with the browser brand's OS keyring key, and an
  automation launch does not have it — Playwright starts browsers with
  `--use-mock-keychain`, so Chrome derives a different key, fails on every row
  and **deletes** them. An unrewritten clone opened once went from 16 cookies to
  2. This also makes the clone brand-independent.
- **Session cookies are given a 12h expiry**, because a browser discards
  cookies with no expiry at startup — and that is where most apps keep the
  actual session.

`sessionStorage` copied into a clone is **not** restored by a normal launch
(per-tab state; the browser starts fresh namespaces). Use the init script for
it even with a clone.

`doctor` is the triage command and the right place to test macOS keychain
access: it asks for the key deliberately, discards it, and reports only whether
the read was permitted. Answer the prompt with **"Allow"**, never **"Always
Allow"**: the latter adds `/usr/bin/security` to the key's access list, after
which any process on the machine reads the browser's key — every cookie of
every site — without asking. `--skip-keyring-probe` checks everything else without
raising a prompt. Exit `1` when something blocking was found.

`profiles` enumerates the stores with the label the human sees next to the
directory name on disk — nobody knows which of their profiles is `Profile 3`.
It reads no cookie and requests no secret, so it never prompts.

## Gotchas

- **`cookies` SameSite is a guess, and mostly harmless.** The store reader does
  not report the attribute, so every exported cookie claims `Lax` — Chrome's own
  default for a cookie that arrived without one. It does **not** affect the
  normal case: a top-level navigation to the cookie's own site sends it whatever
  the label says. It bites only cross-site — a third-party iframe, a cross-site
  POST in an SSO redirect chain, a cross-origin `fetch` — and it fails closed
  ("not logged in"), never open. `--same-site none` is the lever for those
  flows; it is **not applied to non-Secure cookies**, because `SameSite=None`
  without `Secure` makes a browser reject the cookie outright, which on a real
  profile would silently drop the session cookies themselves.
- **`cookies` does not read the WAL.** Chrome keeps recent writes in a
  `Cookies-wal` sidecar this reader ignores, so a cookie set in the last few
  minutes can be legitimately missing. The result warns when a sidecar holds
  data; quit the browser for a complete read.
- **IndexedDB is reported, never exported.** `-j` lists it under `unreadable`
  with its size. If a storageState restores the cookies and the app still asks
  to log in, that is the first thing to suspect — and `--clone-profile` is the
  answer. Service-worker registrations and Cache Storage are neither read nor
  cloned.
- **A clone must be opened by a browser, not read as data.** Its cookie values
  are plaintext and its session cookies have been given an artificial expiry, so
  it is not a faithful copy of the profile — it is a profile built to be
  launched once by an agent. Treat the directory as the credential it is.
- **An empty `cookies` result is not evidence of absence.** Check `problem` /
  `error.code` first: `keyring_denied` means the key was refused, not that the
  domain has none. This is the single most likely way to mis-read the command.
- **`cookies` prompts only when something matches.** Domain and name filters run
  before decryption, so querying a domain the browser has never seen raises no
  approval prompt at all — which is also why a no-match run proves nothing about
  whether access would have been granted.
- **Every read prompts, by design.** Answer "Allow" (this read only). "Always
  Allow" would make the prompt go away by granting every local process the
  browser's key: released binaries ask through `/usr/bin/security`, so the
  standing grant is that binary's, usable by anything that runs it. For an
  unattended run use `--no-prompt`, which fails `keyring_denied` instead of
  waiting on a dialog nobody sees.
- **`cookies --require-match` exits 3 on a miss**, and so does an `-o` run that
  kept an existing file because nothing matched (`output_kept`).
