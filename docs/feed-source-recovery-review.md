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

## Follow-up: three unresolved sources (2026-10-21)

### CISA — HTTP 403, access failure rather than RSS parsing
Production Actions run 39522264804 received HTTP 403 from
`https://www.cisa.gov/cybersecurity-advisories/all.xml`. A separate public
web retrieval of that exact URL also returned HTTP 403. Third-party listings
still document the same CISA URL as an RSS source, so neither a typo nor a
permanent outage can be established.

- Evidence: https://www.cisa.gov/cybersecurity-advisories/all.xml
- Context (non-authoritative monitoring): https://feeder.co/discover/475407592a/cisa-gov
- **No bypass** of anti-bot controls and no blind URL substitution.
- Next: verify CISA's permitted distribution methods and license/terms; test
  a sanctioned fallback separately with mock responses before any proposal.

### Microsoft MSRC — apparent HTML rather than a verified RSS feed
Production logs show zero entries from `https://msrc.microsoft.com/blog/feed`
with no exception. Microsoft's own 2025 blog post explicitly links to
`https://msrc.microsoft.com/blog/rss/` as its MSRC RSS feed; however,
following the link in public web retrieval redirected to the ordinary MSRC
blog landing page (`https://www.microsoft.com/en-us/msrc/blog`).
Neither endpoint has been verified to return usable RSS to GitHub Actions.

- Official reference:
  https://www.microsoft.com/en-us/security/blog/2025/03/13/how-msrc-coordinates-vulnerability-research-and-disclosure-while-building-community/
- Redirected official link: https://msrc.microsoft.com/blog/rss/
- **No switch yet**. Record final URL, status, Content-Type, parser version,
  bozo flag, and entry count in a dedicated, non-production probe when approved.
- Do not conflate the Security Update Guide's separate vulnerability-update
  RSS feed with the MSRC *blog* RSS feed.

### Trend Micro — confirmed official category RSS, scope unverified
Production logs show HTTP 404 from
`https://www.trendmicro.com/en_us/research/rss.xml`.
Trend Micro's official Newsroom has a Research category RSS link:
`https://newsroom.trendmicro.com/news-releases?category=787&pagetemplate=rss`.
The public web reader reported `text/xml` but could not display the XML
payload. The category is under *Newsroom / news-releases*; it cannot be
assumed equivalent to the full Trend Micro Research publication stream.

- Official RSS directory: https://newsroom.trendmicro.com/rss
- Candidate category feed:
  https://newsroom.trendmicro.com/news-releases?category=787&pagetemplate=rss
- **No switch yet**. Verify item count, publication recency, topic
  relevance, and source terms without making production requests.

## Reproducible evidence policy

- Observed HTTP codes are **point-in-time**, not permanent site conditions.
- Source status should represent distinct `transport_error`, `http_error`,
  `invalid_feed`, `valid_empty_feed`, and `valid_nonempty_feed` cases.
  PR #8 handles the valid-empty distinction but this proposal does not alter
  runtime classification.
- Never claim that mocked RSS tests prove remote host availability.
- No writes to main, SQLite, generated reports, ntfy, or the scheduled
  workflow were made during this review.
