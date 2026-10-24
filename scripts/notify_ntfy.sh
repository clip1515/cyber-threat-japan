#!/usr/bin/env bash
# Send the daily summary to ntfy. The body is read from a file and never expanded by the shell.
#
# Required: NTFY_TOPIC, NOTIFY_BODY_FILE. Optional: NTFY_URL (default https://ntfy.sh),
# NTFY_TITLE, NTFY_PRIORITY, NTFY_CONNECT_TIMEOUT, NTFY_MAX_TIME, NTFY_RETRY (default 0),
# NTFY_RETRY_DELAY, NTFY_OUTCOME_FILE (receives the outcome below).
#
# Outcomes and exit codes. A message is reported as not delivered only when there is
# positive evidence that it was not; everything else that is not a clean 2xx is unknown.
#   sent            (0) curl completed normally and the server answered 2xx.
#   failed_definite (1) no request body left this runner (DNS, refused, connect timeout, TLS),
#                       or the server rejected the request before processing it:
#                       400 401 403 404 405 411 413 414 415 429.
#   unknown         (3) anything else: every 5xx (500 may fail after storing; 502/504 come from a
#                       gateway that cannot know), other 3xx/4xx, a 2xx followed by a transport
#                       error, or a request that was sent but never answered.
# Retries are off by default (NTFY_RETRY=0). When enabled, only 429 is retried: it is the one
# answer that says the request was not processed. Retrying an unknown outcome could deliver twice.
set -euo pipefail

: "${NTFY_TOPIC:?NTFY_TOPIC is not set}"
: "${NOTIFY_BODY_FILE:?NOTIFY_BODY_FILE is not set}"

finish() {
  [ -n "${NTFY_OUTCOME_FILE:-}" ] && printf '%s\n' "$1" > "$NTFY_OUTCOME_FILE"
  echo "ntfy: $1 ($2)" >&2
  exit "$3"
}

if [ ! -s "$NOTIFY_BODY_FILE" ]; then
  finish failed_definite "notification body file is missing or empty" 1
fi

retries=${NTFY_RETRY:-0}
attempt=0
while :; do
  attempt=$((attempt + 1))
  set +e
  result=$(curl --silent --show-error --output /dev/null \
    --write-out '%{http_code} %{size_upload}' \
    --connect-timeout "${NTFY_CONNECT_TIMEOUT:-10}" \
    --max-time "${NTFY_MAX_TIME:-30}" \
    -H "Title: ${NTFY_TITLE:-cyber-threat-japan daily update}" \
    -H "Priority: ${NTFY_PRIORITY:-default}" \
    --data-binary @"$NOTIFY_BODY_FILE" \
    "${NTFY_URL:-https://ntfy.sh}/$NTFY_TOPIC")
  rc=$?
  set -e
  read -r status uploaded <<< "$result"
  uploaded=${uploaded%%.*}
  if [ "$rc" -eq 0 ]; then
    case "$status" in
      2??) finish sent "HTTP $status" 0 ;;
      429)
        if [ "$attempt" -le "$retries" ]; then
          sleep "${NTFY_RETRY_DELAY:-5}"
          continue
        fi
        finish failed_definite "HTTP 429 after $attempt attempt(s)" 1 ;;
      400|401|403|404|405|411|413|414|415) finish failed_definite "HTTP $status" 1 ;;
      *) finish unknown "HTTP $status: the server may have accepted the message" 3 ;;
    esac
  fi
  if [ "${status:-000}" = "000" ] && [ "${uploaded:-1}" = "0" ]; then
    finish failed_definite "request not sent, curl exit $rc" 1
  fi
  finish unknown "curl exit $rc after the request was sent (HTTP ${status:-000}); the message may have been delivered" 3
done
