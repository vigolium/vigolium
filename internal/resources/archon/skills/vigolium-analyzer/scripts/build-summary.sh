#!/usr/bin/env bash
set -euo pipefail

VIGOLIUM_DIR="${1:?Usage: build-summary.sh <vigolium_dir>}"

if [ ! -d "$VIGOLIUM_DIR" ]; then
  echo "Error: Directory '$VIGOLIUM_DIR' does not exist" >&2
  exit 1
fi

OUTPUT_FILE="$VIGOLIUM_DIR/summary.tsv"

printf "db_path\tuuid\tmethod\turl\tstatus_code\tcontent_type\ttitle\twords\ttechnology\tsource\n" > "$OUTPUT_FILE"

db_count=0
for db_file in "$VIGOLIUM_DIR"/*.db; do
  [ -f "$db_file" ] || continue
  [[ "$db_file" == *-journal ]] && continue

  db_count=$((db_count + 1))

  sqlite3 -separator $'\t' "$db_file" "
    SELECT
      '$db_file',
      uuid,
      COALESCE(method, ''),
      COALESCE(url, ''),
      COALESCE(status_code, 0),
      COALESCE(response_content_type, ''),
      COALESCE(response_title, ''),
      COALESCE(response_words, 0),
      COALESCE(technology, ''),
      COALESCE(source, '')
    FROM http_records;
  " >> "$OUTPUT_FILE" 2>/dev/null || echo "Warning: skipped $db_file (corrupt or locked)" >&2
done

line_count=$(($(wc -l < "$OUTPUT_FILE") - 1))
echo "Summary built: $OUTPUT_FILE"
echo "Total records: $line_count (from $db_count DBs)"
