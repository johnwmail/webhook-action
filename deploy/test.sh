#!/usr/bin/env bash
# Send a signed test webhook to webhook-action.
#
# Usage:
#   ./deploy/test.sh KEY=VALUE [KEY=VALUE ...]
#
# Examples:
#   ./deploy/test.sh tag=v1.2.3
#   ./deploy/test.sh tag=v1.2.3 region=us-east-1
#
# How it works:
#   Each KEY=VALUE argument becomes a JSON field in the webhook payload.
#   webhook-action injects every field into the deploy script's environment as
#   WEBHOOK_PARAM_<KEY> (uppercased), so `tag=v1.2.3` arrives in webhook-action.sh as
#   $WEBHOOK_PARAM_TAG.
#
# Overrides:
#   SECRET=...  URL=http://host:9000/action/webhook ./deploy/test.sh tag=v1.2.3
#   (defaults: secret from ~/.config/webhook-action/webhook-action.env,
#              URL http://127.0.0.1:9000/action/webhook)
set -euo pipefail

if [ "$#" -eq 0 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
  sed -n '2,$s/^# \{0,1\}//p' "$0"
  exit 0
fi

URL="${URL:-http://127.0.0.1:9000/action/webhook}"
SECRET="${SECRET:-$(sed -n 's/^WEBHOOK_SECRET=//p' "$HOME/.config/webhook-action/webhook-action.env")}"
[ -n "${SECRET}" ] || { echo "error: set SECRET or WEBHOOK_SECRET in webhook-action.env" >&2; exit 1; }

parts=()
for kv in "$@"; do parts+=("\"${kv%%=*}\":\"${kv#*=}\""); done
body="{$(IFS=,; echo "${parts[*]}")}"
echo "-> POST $URL"
echo "-> payload: $body (webhook-action.sh receives WEBHOOK_PARAM_* for each field)"

sig="sha256=$(printf '%s' "$body" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $2}')"
curl -i -X POST "$URL" \
  -H 'Content-Type: application/json' \
  -H "X-Hub-Signature-256: $sig" \
  -d "$body"