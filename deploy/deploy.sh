#!/usr/bin/env bash
# Example deploy script run by webhook-action.
#
# The webhook server forwards every JSON field of the GitHub payload as an
# environment variable named WEBHOOK_PARAM_<UPPERCASED_KEY>, e.g.:
#   { "ref": "refs/tags/v1.2.3", "tag": "v1.2.3" }
# becomes WEBHOOK_PARAM_REF and WEBHOOK_PARAM_TAG inside this script.
#
# Tailor everything below to your own project.
set -euo pipefail

TAG="${WEBHOOK_PARAM_TAG:-}"
REF="${WEBHOOK_PARAM_REF:-}"
ACTOR="${WEBHOOK_PARAM_ACTOR:-unset}"

echo "[deploy] started by '${ACTOR}' tag='${TAG}' ref='${REF}'"

REPO_DIR="${REPO_DIR:-${HOME}/my-app}"
SYSTEMD_SERVICE="${SYSTEMD_SERVICE:-my-app.service}"

if [ ! -d "${REPO_DIR}/.git" ]; then
  echo "[deploy] error: '${REPO_DIR}' is not a git repository" >&2
  exit 1
fi

cd "${REPO_DIR}"

# Keep the checkout in sync with the event that triggered us.
git fetch --all --prune
if [ -n "${TAG}" ]; then
  git checkout "refs/tags/${TAG}" --
elif [ -n "${REF}" ]; then
  git checkout "${REF}" --
else
  git pull --ff-only
fi

# --- Example steps (comment out / replace with your real build) ---
# make build
# ./scripts/migrate.sh
# systemctl restart "${SYSTEMD_SERVICE}"

echo "[deploy] finished"