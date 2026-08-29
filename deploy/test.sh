#!/usr/bin/env bash
# Manual smoke test for webhook-action using curl.
#
# Sends signed and unsigned requests to a running webhook-action server and
# checks the HTTP status codes.
#
# Usage:
#   ./deploy/test.sh                     # uses ~/.config/webhook-action/webhook-action.env
#   SECRET=mysecret ./deploy/test.sh     # override the secret
#   URL=http://host:9000/action/webhook ./deploy/test.sh   # override the endpoint
set -euo pipefail

BASE_URL="${URL:-http://127.0.0.1:9000/action/webhook}"
SECRET="${SECRET:-}"

if [ -z "${SECRET}" ] && [ -f "${HOME}/.config/webhook-action/webhook-action.env" ]; then
  SECRET="$(sed -n 's/^WEBHOOK_SECRET=//p' "${HOME}/.config/webhook-action/webhook-action.env")"
fi

if [ -z "${SECRET}" ] || [ "${SECRET}" = "change-me-to-a-64-char-hex-secret" ]; then
  echo "[test] error: set SECRET (or WEBHOOK_SECRET in your webhook-action.env)" >&2
  exit 1
fi

# Demo payload. Every key is forwarded to the deploy script as an environment
# variable (DEPLOY_PARAM_<UPPERCASED_KEY>), so a valid delivery sets for example:
#   DEPLOY_PARAM_REF=refs/tags/v1.2.3
#   DEPLOY_PARAM_TAG=v1.2.3
#   DEPLOY_PARAM_ACTOR=octocat
#   DEPLOY_PARAM_ACTION=published
#   DEPLOY_PARAM_REPOSITORY=webhook-action
#   DEPLOY_PARAM_ENVIRONMENT=production
#   DEPLOY_PARAM_REGION=ap-southeast-1
#   DEPLOY_PARAM_FORCE_DEPLOY=true
body='{"ref":"refs/tags/v1.2.3","tag":"v1.2.3","actor":"octocat","action":"published","repository":"webhook-action","environment":"production","region":"ap-southeast-1","force_deploy":true}'

sign() {
  printf '%s' "$1" | openssl dgst -sha256 -hmac "${SECRET}" | awk '{print $2}'
}

status() {
  curl -s -o /dev/null -w '%{http_code}' "$@"
}

pass=0
fail=0

check() {
  local name="$1" want="$2" got="$3"
  if [ "${got}" = "${want}" ]; then
    pass=$((pass + 1))
    printf 'PASS  %-20s got %s\n' "${name}" "${got}"
  else
    fail=$((fail + 1))
    printf 'FAIL  %-20s want %s got %s\n' "${name}" "${want}" "${got}"
  fi
}

sig="sha256=$(sign "${body}")"
check "valid signature" 200 "$(status -X POST "${BASE_URL}" -H 'Content-Type: application/json' -H "X-Hub-Signature-256: ${sig}" -d "${body}")"

check "missing signature" 401 "$(status -X POST "${BASE_URL}" -H 'Content-Type: application/json' -d "${body}")"

check "wrong signature" 403 "$(status -X POST "${BASE_URL}" -H 'Content-Type: application/json' -H "X-Hub-Signature-256: sha256=$(sign wrong)" -d "${body}")"

bad_json='{"tag": "v1.2.3"'
bad_sig="sha256=$(sign "${bad_json}")"
check "invalid json" 400 "$(status -X POST "${BASE_URL}" -H 'Content-Type: application/json' -H "X-Hub-Signature-256: ${bad_sig}" -d "${bad_json}")"

check "GET not allowed" 405 "$(status "${BASE_URL}")"

echo
echo "[test] ${pass} passed, ${fail} failed"
[ "${fail}" -eq 0 ]