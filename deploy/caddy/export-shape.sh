#!/bin/sh
# Writes the shape of Caddy's live routes (no secrets) for helmsman-security.
# Fails closed: on any error the previous file is left untouched, so it ages
# out and the engine reports exposure as unknown rather than using bad data.
set -eu

ADMIN_URL="${HS_CADDY_ADMIN_URL:-http://localhost:2019/config/}"
FILTER="${HS_CADDY_FILTER:-/usr/local/share/hs-caddy/shape.jq}"
OUT="${HS_CADDY_OUT:-/var/lib/hs-caddy/shape.json}"

dir=$(dirname "$OUT")
raw=$(mktemp "$dir/.raw.XXXXXX")
new=$(mktemp "$dir/.new.XXXXXX")
trap 'rm -f "$raw" "$new"' EXIT

# 1. Fetch. --fail turns an HTTP error into a non-zero exit.
curl --fail --silent --show-error --max-time 10 -o "$raw" "$ADMIN_URL"

# 2. Reduce. A separate step, so a jq failure can't be masked by curl's status.
jq -f "$FILTER" "$raw" > "$new"

# 3. Validate before replacing anything.
jq -e '.version == 2
  and (.generatedAt | type == "number")
  and (.servers | type == "array" and length > 0)
  and ([.servers[].routes[]?] | length > 0)' "$new" > /dev/null

# 4. Replace atomically.
chmod 0644 "$new"
mv -f "$new" "$OUT"
