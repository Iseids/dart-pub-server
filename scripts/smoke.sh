#!/usr/bin/env sh
set -eu
BASE="${1:-https://pub.iseids.com}"
BASE="${BASE%/}"
printf 'Checking %s/healthz\n' "$BASE"
curl --fail --silent --show-error "$BASE/healthz"
printf '\nChecking Pub v2 missing-package behavior\n'
STATUS="$(curl -s -o /dev/null -w '%{http_code}' -H 'Accept: application/vnd.pub.v2+json' "$BASE/api/packages/does_not_exist_here")"
if [ "$STATUS" = 404 ]; then
  echo 'OK: missing packages return 404'
elif [ "$STATUS" = 401 ]; then
  echo 'OK: private registry requires authentication'
else
  echo "Unexpected HTTP $STATUS" >&2
  exit 1
fi
