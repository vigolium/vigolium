---
name: vigolium-analyzer
description: Analyzes vigolium security scanner SQLite databases to surface unauthenticated admin panels, API data leaks, missing parameter disclosures, and debug exposures. Produces severity-ranked finding reports with CVSS 3.1 scoring.
argument-hint: "<base_path> [domain]"
---

# Vigolium DB Analyzer

You are the orchestrator for analyzing vigolium security scanner SQLite databases. You run a two-round analysis: **Recon** (parallel discovery) then **Audit** (verification + active testing).

## Arguments
- `$ARGUMENTS` contains: `<base_path> [domain]`
  - `base_path`: root directory containing domain folders with vigolium data
  - `domain`: optional, specific domain to analyze

Parse arguments:
```bash
ARGS=($ARGUMENTS)
BASE_PATH="${ARGS[0]:-}"
DOMAIN="${ARGS[1]:-}"
```

If no base_path provided, ask the user for it.

## Summary TSV Column Reference (10 columns)

```
col1:db_path  col2:uuid  col3:method  col4:url  col5:status_code  col6:content_type  col7:title  col8:words  col9:technology  col10:source
```
- Columns separated by `\t`. Lines end with `\n`.
- `words` is col8, NOT the last column. Match zero words with `$'\t0\t'` (tab-0-tab), NOT `$'\t0$'`.
- `title` (col7) and `content_type` (col6) may be empty (consecutive tabs `\t\t`).
- First line is header — skip with `tail -n +2`.

---

## RECON ROUND

### Step 1: Find Vigolium Directory

```bash
VIGOLIUM_DIR=$(bash {baseDir}/scripts/find-vigolium.sh "$BASE_PATH" "$DOMAIN")
```

If no domain specified, list all available domains:
```bash
bash {baseDir}/scripts/find-vigolium.sh "$BASE_PATH"
```
Ask user to pick a domain.

### Step 2: Build Summary TSV

```bash
bash {baseDir}/scripts/build-summary.sh "$VIGOLIUM_DIR"
wc -l "$VIGOLIUM_DIR/summary.tsv"
```

### Step 3: Spawn 5 Recon Agents in Parallel

All 5 agents run simultaneously. Each reads `summary.tsv` independently and writes its own candidates file.

Spawn all 5 agents in a **single message** with the Agent tool:

**Agent 1 — vigolium-recon-titles** (Title Discovery):
```
VIGOLIUM_DIR: <vigolium_dir>
SUMMARY_FILE: <vigolium_dir>/summary.tsv
OUTPUT_FILE: <vigolium_dir>/candidates_pass1.tsv
```

**Agent 2 — vigolium-recon-empty-titles** (Empty-Title Records):
```
VIGOLIUM_DIR: <vigolium_dir>
SUMMARY_FILE: <vigolium_dir>/summary.tsv
OUTPUT_FILE: <vigolium_dir>/candidates_pass2.tsv
```

**Agent 3 — vigolium-recon-api** (API/Data Responses):
```
VIGOLIUM_DIR: <vigolium_dir>
SUMMARY_FILE: <vigolium_dir>/summary.tsv
OUTPUT_FILE: <vigolium_dir>/candidates_pass3.tsv
```

**Agent 4 — vigolium-recon-errors** (Error Responses):
```
VIGOLIUM_DIR: <vigolium_dir>
SUMMARY_FILE: <vigolium_dir>/summary.tsv
OUTPUT_FILE: <vigolium_dir>/candidates_pass4.tsv
```

**Agent 5 — vigolium-recon-anomalies** (Anomalies):
```
VIGOLIUM_DIR: <vigolium_dir>
SUMMARY_FILE: <vigolium_dir>/summary.tsv
OUTPUT_FILE: <vigolium_dir>/candidates_pass5.tsv
```

### Step 4: Wait for All Recon Agents

Wait for all 5 agents to complete. Do not proceed until all are done.

### Step 5: Merge + Dedup Candidates

```bash
sort -t$'\t' -k2,2 -u "$VIGOLIUM_DIR"/candidates_pass*.tsv > "$VIGOLIUM_DIR/all_candidates.tsv"
wc -l "$VIGOLIUM_DIR/all_candidates.tsv"
```

Read `all_candidates.tsv` to review what was found.

---

## AUDIT ROUND

### Step 6: Prioritize Candidates

Read `all_candidates.tsv` and assign priority:
- **Priority 1 (Critical):** admin panels/CMS/portals with status 200 + high words
- **Priority 2 (High):** swagger_spec, cloud_storage, API endpoints with JSON + high words
- **Priority 3 (Medium):** Error responses with params, debug pages
- **Priority 4 (Low):** Anomalies, edge cases

### Step 7: Dynamic Batching + Spawn Audit Agents

Assess complexity of each candidate:
- **Simple** (fetch + read): admin panels, debug pages → batch up to 20
- **Medium** (fetch + 1-2 curl tests): API leaks, method testing → batch 10-15
- **Complex** (spec testing, bucket enumeration, multi-param fuzzing): swagger_spec, cloud_storage, missing params → batch 5-8
- Minimum 5 per batch always

Create finding directory:
```bash
mkdir -p "$VIGOLIUM_DIR/finding"
```

For each batch, spawn a **vigolium-audit** agent in background with a unique BATCH_ID:

```
VIGOLIUM_DIR: <vigolium_dir>
BATCH_ID: batch_001
FINDING_DIR: <vigolium_dir>/finding
FETCH_SCRIPT: {baseDir}/scripts/fetch-record.sh

RECORDS TO AUDIT:
1. db_path=<path> uuid=<uuid> url=<url> status=<code> type=<content_type> title=<title> words=<count> category=<category> reason=<reason>
2. ...
```

Each audit agent writes findings to `finding/batch_NNN/` exclusively — no shared files.

Spawn Priority 1+2 batches first, then 3+4. Continue spawning while previous agents run.

### Step 8: Wait for All Audit Agents

Wait for all audit agents to complete.

### Step 9: Merge Batch Folders → Final Findings

```bash
FINDING_DIR="$VIGOLIUM_DIR/finding"
counter=0

# Move .md findings from batch folders to root finding dir with numbered names
for batch_dir in "$FINDING_DIR"/batch_*/; do
  [ -d "$batch_dir" ] || continue
  for f in "$batch_dir"*.md; do
    [ -f "$f" ] || continue
    counter=$((counter + 1))
    basename_f=$(basename "$f")
    severity="${basename_f%%-*}"
    rest="${basename_f#*-}"
    mv "$f" "$FINDING_DIR/${severity}$(printf '%03d' $counter)-${rest}"
  done
  rm -rf "$batch_dir"
done
```

### Step 10: Summary

```bash
echo "=== Findings Summary ==="
for sev in C H M L I; do
  count=$(find "$FINDING_DIR" -maxdepth 1 -name "${sev}*.md" 2>/dev/null | wc -l)
  echo "$sev: $count"
done
total=$(find "$FINDING_DIR" -maxdepth 1 -name "*.md" 2>/dev/null | wc -l)
echo "Total: $total"
find "$FINDING_DIR" -maxdepth 1 -name "*.md" | sort
```

Report findings to the user.