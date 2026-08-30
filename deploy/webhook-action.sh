#!/usr/bin/env bash
# Example deploy script run by webhook-action.
#
# webhook-action injects every field of the webhook payload into this script's
# environment as WEBHOOK_PARAM_<KEY>, e.g. for a payload like
#   {"ref": "refs/tags/v1.2.3", "tag": "v1.2.3", "actor": "octocat"}
# you get WEBHOOK_PARAM_REF, WEBHOOK_PARAM_TAG, and WEBHOOK_PARAM_ACTOR.
#
# Replace the echo below with your real deployment steps.
set -euo pipefail

echo "[deploy] tag=${WEBHOOK_PARAM_TAG:-} ref=${WEBHOOK_PARAM_REF:-} actor=${WEBHOOK_PARAM_ACTOR:-unset}"