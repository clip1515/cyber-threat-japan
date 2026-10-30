# Isolated integration audit: PR #8 + PR #10

Date: 2026-10-21 JST. This is a **Draft-only synthetic validation branch**.
Parent: PR #8 head `3017634d02059b0336bf86034d0d794d6bb64bcb`.
Added: nine changed-file blobs from PR #10 head
`10c9c3c5f614d77a929b3bd175b801cd08d896a2`.
Both PRs target unchanged main `a85fc96ba1d57cf47f06af1592d796cc06a263d3`.

## Safety controls
- No main update, merge, production SQLite write or daily workflow dispatch.
- No changes to PR #8 or #10 heads.
- Only test/PR-safety GitHub Actions eligible on this branch.
- PR #10's read-only live-probe workflow step is gated to
  `github.head_ref == 'audit/feed-source-recovery'`; it must not run in
  this combined PR.
- The earlier 134 passed/29 subtests for PR #8 and 109 passed/29 subtests
  for PR #10 are **separate** results, not proof the combined tree passes.
- GitHub API writes may not automatically trigger Actions; inspect checks
  and mark integrated CI as **UNVERIFIED** until an actual job succeeds.

## Integration points to scrutinize
1. `update.py`: NORMAL / DEGRADED / FAILED classification when RSS
   responses are valid empty (0 entries), invalid HTML, 403 or 301 redirects.
2. `config/sources.yaml`: IPA RSS 1.0, Mandiant RSS 2.0 and Trend
   Newsroom Research-category RSS 2.0; preserve source IDs and label provenance.
3. `database/db.py` + `update.process_item`: same URL merges;
   same CVE can merge; different URL and no CVE can duplicate articles.
4. `reporting/publish_outputs.py`: previous report/JSON rollback and
   report archive path retention on publication failure.
5. `.github/workflows/daily.yml`: no premature notification on a FAILED
   run and no accidental data write on a non-main branch.
6. CISA HTTP 403 and MSRC HTTP 301 remain explicitly incomplete;
   no bypass or unverified replacement.

## Independent Claude review request

Review this Draft PR #11 and parent Draft PRs #8/#10 **read-only**.
Search for cross-branch integration regressions, unsafe GitHub Actions
expression handling, report/JSON integrity, source classification and
deduplication edge cases. For each finding supply a path, line, concrete
synthetic reproduction and severity. State which files/results were actually
checked. Do not edit any branch, merge, deploy, trigger the daily workflow,
send notifications, or submit external data.
