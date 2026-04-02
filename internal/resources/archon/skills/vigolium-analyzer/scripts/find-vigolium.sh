#!/usr/bin/env bash
set -euo pipefail

BASE_PATH="${1:?Usage: find-vigolium.sh <base_path> [domain]}"
DOMAIN="${2:-}"

if [ ! -d "$BASE_PATH" ]; then
  echo "Error: Base path '$BASE_PATH' does not exist" >&2
  exit 1
fi

if [ -n "$DOMAIN" ]; then
  # Find vigolium dirs matching the domain
  find "$BASE_PATH" -type d -name "vigolium" -path "*/$DOMAIN/*" 2>/dev/null | head -1
else
  # List all domains that have vigolium dirs with .db files
  printf "%-40s\t%s\t%s\n" "DOMAIN" "DBS" "RECORDS"
  printf "%-40s\t%s\t%s\n" "------" "---" "-------"

  find "$BASE_PATH" -type d -name "vigolium" 2>/dev/null | sort | while read -r vdir; do
    domain_dir=$(dirname "$vdir")
    domain=$(basename "$domain_dir")

    db_count=0
    total_records=0

    for db_file in "$vdir"/*.db; do
      [ -f "$db_file" ] || continue
      db_count=$((db_count + 1))
      count=$(sqlite3 "$db_file" "SELECT COUNT(*) FROM http_records;" 2>/dev/null || echo 0)
      total_records=$((total_records + count))
    done

    [ "$db_count" -gt 0 ] && printf "%-40s\t%d\t%d\n" "$domain" "$db_count" "$total_records"
  done
fi
