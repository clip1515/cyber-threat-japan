# Threat model for cyber-threat-japan

## Security purpose
Defensive Japan-focused open-source threat-intelligence ingestion and static
reporting. Inputs are untrusted RSS/Atom/JSON/API content from the public
Internet; the system normalizes data to SQLite and renders Markdown and JSON.

## Security boundaries
- Browser: prevent stored/DOM XSS, HTML/SVG injection, unsafe links, and crashes
  caused by malformed or unexpectedly typed advisory metadata.
- Collection: reject malformed responses; mitigate resource exhaustion, SSRF,
  redirects, and supply-chain hazards where technically relevant.
- Database: prevent SQL injection, data corruption, unsafe writes and false
  attribution of incidents to Japan.
- Publication: distinguish healthy/degraded/failed source coverage and avoid
  silently publishing stale, corrupt, or incomplete run results as normal.
- GitHub Actions: protect workflow permissions, tokens, secrets, generated
  SQLite, artifacts, and git pushes; prevent unsafe concurrency and injection.
- Notifications: prevent shell injection, secret disclosure, and false success.

## Scope and reproduction
Review collectors, analyzers, parsers, reporting, SQLite, dashboard JS,
workflows and notification/publisher scripts. Reproduce with synthetic test
fixtures; do not run live collection, send real notifications, or alter the
production database.

The audit Dockerfile excludes live data/, docs/data/, reports/, logs/,
daily_report.md, credentials, and .git.

Provide paths/lines, reproducible evidence, exploitation prerequisites,
impact, mitigation, and explicitly label all unverified claims.
