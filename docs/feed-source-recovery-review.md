# Source feed recovery — offline review (2026-10-21)

This branch is a **draft-only** configuration repair proposal. It does not
change the production main branch, run collection, or edit the SQLite database.

The latest examined production job is GitHub Actions run 39522264804
(2026-10-21 UTC). It logged 12 successes and 5 failures.

| ID | Production observation | Action in this draft |
| --- | --- | --- |
| ipa_security | HTTP 404 at old RSS URL | Replace with official IPA security alerts RDF URL |
| cisa_advisories | HTTP 403 | No change: identify restriction/authorized source first |
| trendmicro_research | HTTP 404 | No change until current official feed is verified |
| msrc_blog | Parsed 0 entries with no HTTP exception | No change: inspect response format and entry count |
| mandiant_blog | Parsed 0 entries with no HTTP exception | Replace with RSS URL linked on Google Threat Intelligence blog |

Authoritative page links:
- IPA official security RSS: https://www.ipa.go.jp/security/ (links to https://www.ipa.go.jp/security/alert-rss.rdf)
- Google Threat Intelligence: https://cloud.google.com/blog/topics/threat-intelligence
  (its feed link points to https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v).

**Verification levels**: Official-page links are confirmed; XML/RDF content
types were observed with web retrieval, but GitHub Actions network access,
current entry counts, and future feed stability are *not* established.
Test fixtures are synthetic and do not prove real external ingestion.

The current main implementation counts any successfully downloaded empty feed
as a failed source. PR #8 separately addresses this quality-gate issue; do
not apply PR #8 implicitly with this feed URL draft.

**Next safe step**: review the CI regression results, examine upstream feed
metadata without changing production, and get explicit approval before merge.
No workflow_dispatch or notification experiments are part of this draft.
