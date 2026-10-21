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

## Offline feed-body classifier

`scripts/feed_response_probe.py` is a **strictly local**, opt-in diagnostic.
It never sends HTTP requests, writes SQLite, publishes reports, or notifies.
It accepts a previously saved response *body* with an independently observed
HTTP status and reports only state, count, and RSS/Atom parser format:

```bash
python scripts/feed_response_probe.py --body-file /path/to/synthetic-feed.xml --status 200
```

Results are `transport_error` (only when the classifier is called in Python
with no HTTP status), `http_error`, `invalid_feed`, `valid_empty_feed`, or
`valid_nonempty_feed`. For privacy, it does not print the body, headers,
source URL, or article titles. Saved response bodies may still contain
third-party or sensitive content, so do not commit or upload them.
The command has no network access and the CI exercises synthetic XML only.

The command cannot diagnose redirects, DNS/TLS, headers or GitHub-hosted
connectivity on its own. Those must be observed separately and authorized
before any live network probe; do not trigger daily production collection.

## GitHub Actions live connectivity evidence (2026-10-21)

**Verified from isolated PR CI runner** (not the production daily
collection job): workflow runs 39561645242 and 39562001366.

| Diagnostic endpoint | Run 39562001366 observed result | Interpretation |
| --- | --- | --- |
| IPA official alert RDF | RSS 1.0, 30 entries | Working from GitHub Actions |
| Google/Mandiant official feed | RSS 2.0, 20 entries | Working from GitHub Actions |
| Existing CISA advisories RSS | HTTP 403 | Access denied; no bypass attempted |
| Existing Trend Research RSS | HTTP 404 | Broken old URL |
| Existing MSRC blog /feed | HTTP 301 | Redirect; not followed |
| MSRC official /blog/rss/ candidate | HTTP 301 | Redirect; not followed |
| Trend Newsroom Research category candidate | RSS 2.0, 25 entries | Working technically; editorial scope is not established |

The probe makes one bounded HTTPS GET to each hardcoded public endpoint,
uses no credentials and follows no redirects. It outputs status and aggregate
parser counts only, does not store fetched content, and never calls update.py,
opens production databases or sends notifications.

**Publication remains blocked** until a separate review approves feed
replacement and the PR is explicitly merged. A successful Newsroom category
feed is not automatically a full substitute for threat-intelligence research.
This document contains only metadata confirmed by CI logs; no unverified
article-level equivalence is claimed.

## Claude independent review and bounded follow-up (2026-10-21)

Claude independently reported that Trend Micro's official RSS directory
links to the Research category endpoint with query
`pagetemplate=rss&category=787`. The independent reviewer also observed
25 entries, including security research announcements, and explicitly did
**not** establish that the category exactly replaces the historical
Trend Micro Research blog. Separate GitHub Actions run 39562001366
confirmed RSS 2.0 and 25 entries from this candidate.

Accordingly, this *draft* now proposes the official Newsroom category
feed under a scoped source name:
`Trend Micro Newsroom - Research (Press Releases)`.
It deliberately does not claim coverage-equivalence or expand the trust
level. The source ID is retained to avoid accidental database identity
changes; its article provenance in new data must be reviewed before merge.
Previously stated "No change" entries above refer to earlier review stages.

Claude also reported MSRC `/blog/feed` and `/blog/rss/` redirecting to
a regular Microsoft blog landing page, and that `/feed` returned a
"Content Not Found" placeholder. These were independent-tool
observations, not independently confirmed by the GitHub Actions probe,
which intentionally does not follow redirects. MSRC stays unchanged.

CISA's May 2025 public announcement described temporary suspension of
planned alert-delivery changes; it did **not** establish withdrawal of the
specific Cybersecurity Advisories RSS URL. No official alternative has
been validated and the HTTP 403 seen on GitHub Actions is not attributed
to an unverified anti-bot cause. CISA stays unchanged.

Authoritative references:
- https://newsroom.trendmicro.com/rss
- https://newsroom.trendmicro.com/news-releases?pagetemplate=rss&category=787
- https://www.cisa.gov/news-events/alerts/2025/05/12/update-how-cisa-shares-cyber-related-alerts-and-notifications

Still **not** authorized: merge, production runs, main edits, database
writes, notification delivery, or live scraping beyond the reviewed
single-request diagnostic.
