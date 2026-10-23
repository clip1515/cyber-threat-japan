#!/usr/bin/env bash
# Commit generated data and publish it to main without mixing it with other generated data.
#
# Replaces `git pull --rebase origin main && git push`: that rebased this run's data onto
# whatever main had, which could publish a feature branch's commits to main, merge a newer
# report or dashboard with this run's text, or republish a stale run. Here the run publishes
# only from main, only if its checkout is still an ancestor of main, and only if nothing on
# main changed the generated paths since the checkout. Code-only commits are rebased over.
#
# Only an explicit allowlist of generated files can be published. Anything else that appears
# under the generated directories (credentials, SQLite -wal/-shm/-journal files, logs, files
# ignored by .gitignore), any deletion or rename there, and anything already staged in the
# index stops the publish instead of being committed or silently skipped. The staged set is
# checked again before committing, so a refused publish leaves no local commit with such a file.
#
# Every git query writes to a file and its exit status is checked: a failed `git status` or
# `git diff` prints nothing, and reading that as "no changes" would skip a check or report a
# publish that never happened. Any git failure stops the publish with a non-zero exit.
set -euo pipefail

GENERATED=(data daily_report.md reports docs/data)
ALLOWED_RE='^(data/threat_intel\.db|daily_report\.md|docs/data/dashboard_data\.json|reports/daily_report_([0-9]{4}-[0-9]{2}-[0-9]{2}|unknown-date)_run[0-9]+\.md)$'

fail() {
  echo "Refusing to publish: $*" >&2
  exit 1
}

# Prints the first path in a NUL-separated list file that is not an allowed generated file
# (or "(no files)" for an empty list) and returns 1; returns 0 if every path is allowed.
first_disallowed() {
  local path found=0
  while IFS= read -r -d '' path; do
    found=1
    if ! [[ "$path" =~ $ALLOWED_RE ]]; then
      printf '%s' "$path"
      return 1
    fi
  done < "$1"
  if [ "$found" -eq 0 ]; then
    printf '(no files)'
    return 1
  fi
}

if [ "${GITHUB_REF:-}" != "refs/heads/main" ]; then
  echo "Refusing to publish from ${GITHUB_REF:-an unknown ref}; only refs/heads/main may publish." >&2
  exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

base=$(git rev-parse --verify HEAD) || fail "git rev-parse HEAD failed."
rc=0
git diff --cached --quiet || rc=$?
case "$rc" in
  0) ;;
  1)
    echo "Refusing to publish: the index already has staged changes:" >&2
    git diff --cached --name-only >&2 || true
    exit 1
    ;;
  *) fail "git diff --cached failed (exit $rc)." ;;
esac

git status --porcelain=v1 -z --untracked-files=all --ignored=traditional -- "${GENERATED[@]}" > "$work/status" \
  || fail "git status failed (exit $?)."
publish=()
rejected=()
while IFS= read -r -d '' entry; do
  code=${entry:0:2}
  path=${entry:3}
  if [[ "$code" == *R* || "$code" == *C* ]]; then
    IFS= read -r -d '' _ || true  # the rename/copy source path follows as its own field
    rejected+=("$code $path")
  elif [[ "$code" == *D* || "$code" == *U* || "$code" == "!!" ]] || ! [[ "$path" =~ $ALLOWED_RE ]]; then
    rejected+=("$code $path")
  else
    publish+=("$path")
  fi
done < "$work/status"
if [ "${#rejected[@]}" -gt 0 ]; then
  echo "Refusing to publish: changes under the generated paths that are not allowed generated files:" >&2
  printf '  %s\n' "${rejected[@]}" >&2
  exit 1
fi
if [ "${#publish[@]}" -eq 0 ]; then
  echo "No changes to commit."
  exit 0
fi

git add -- "${publish[@]}"
git diff --cached --name-only -z --no-renames > "$work/staged" || fail "git diff --cached failed (exit $?)."
if ! bad=$(first_disallowed "$work/staged"); then
  git reset -q || true  # unstage; nothing has been committed
  fail "the index would commit $bad, which is not an allowed generated file."
fi
git commit -m "chore: daily update $(date -u +%Y-%m-%d)" -- "${publish[@]}"
git diff-tree --no-commit-id --name-only -r -z --no-renames HEAD > "$work/committed" \
  || fail "git diff-tree failed (exit $?)."
if ! bad=$(first_disallowed "$work/committed"); then
  git reset -q "$base" || true  # drop the local commit; the working tree is left as it was
  fail "the commit contains $bad, which is not an allowed generated file."
fi

git fetch origin main
rc=0
git merge-base --is-ancestor "$base" FETCH_HEAD || rc=$?
case "$rc" in
  0) ;;
  1) fail "the checked-out commit $base is not on main." ;;
  *) fail "git merge-base failed (exit $rc)." ;;
esac
git diff --name-only -z "$base" FETCH_HEAD -- "${GENERATED[@]}" > "$work/main_generated" \
  || fail "git diff against main failed (exit $?)."
if [ -s "$work/main_generated" ]; then
  fail "main has newer generated data. Re-run the collection from the latest main."
fi
git rebase FETCH_HEAD

# What is pushed: exactly one commit on top of main, touching only allowed generated files.
git rev-list FETCH_HEAD..HEAD > "$work/outgoing" || fail "git rev-list failed (exit $?)."
[ "$(wc -l < "$work/outgoing")" -eq 1 ] || fail "expected exactly one commit to push."
git diff --name-only -z --no-renames FETCH_HEAD HEAD > "$work/outgoing_files" || fail "git diff failed (exit $?)."
if ! bad=$(first_disallowed "$work/outgoing_files"); then
  fail "the push would contain $bad, which is not an allowed generated file."
fi
git push origin HEAD:main
