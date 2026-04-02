#!/usr/bin/env bash
set -euo pipefail

DB_PATH="${1:?Usage: fetch-record.sh <db_path> <uuid>}"
UUID="${2:?Usage: fetch-record.sh <db_path> <uuid>}"

if [ ! -f "$DB_PATH" ]; then
  echo "Error: Database '$DB_PATH' does not exist" >&2
  exit 1
fi

echo "=== Record: $UUID ==="
echo "=== DB: $DB_PATH ==="
echo ""

# Fetch metadata
sqlite3 -header -separator $'\t' "$DB_PATH" "
  SELECT method, url, status_code, response_content_type, response_title, response_words, request_authorization, technology, source
  FROM http_records
  WHERE uuid = '$UUID';
"

echo ""
echo "=== Response Headers ==="
sqlite3 "$DB_PATH" "
  SELECT response_headers FROM http_records WHERE uuid = '$UUID';
"

echo ""
echo "=== Response Body (first 3000 chars) ==="
sqlite3 "$DB_PATH" "
  SELECT SUBSTR(CAST(response_body AS TEXT), 1, 3000) FROM http_records WHERE uuid = '$UUID';
"

echo ""
echo "=== Raw Request ==="
sqlite3 "$DB_PATH" "
  SELECT SUBSTR(CAST(raw_request AS TEXT), 1, 1000) FROM http_records WHERE uuid = '$UUID';
"
