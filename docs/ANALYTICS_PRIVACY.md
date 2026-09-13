# Analytics and privacy

ThreatVeil measures its own product usage from the records it already keeps. There is no
browser tracker, no third-party analytics script, no session recording and no device
fingerprinting — in the marketing site or in the workspace.

## What is measured, and where it comes from

| Measurement | Source | Scope |
|---|---|---|
| Activation milestones and the funnel | the tenant's own records (systems, sources, baselines, decisions, changes, feedback) | one organization |
| Consequence provenance and precision | `consequence_feedback` and the deterministic change views | one organization |
| RPS (watched / maintained / relied upon) | source batches, the clearance lifecycle, and minimized reliance counters | one organization |
| Gate and passport reliance | `service_metric` records: a name, a bucket, and bounded dimensions | one organization |
| AI cost | `ai_usage` records: provider, model, feature, tokens, latency, estimated cost | one organization |
| Commercial measurement | the operator-only store (staff time, classification, prospects, offers) | ThreatVeil internal, never in a tenant's view |

Everything in the first five rows is computed **server-side, per tenant, on request**. Nothing is
precomputed into a cross-customer warehouse, because no such warehouse exists.

## Service metrics are minimized by construction

A reliance counter records: the metric name, an hourly bucket, and bounded dimensions (a system
id, an environment id, a passport or share id, and a consumer label matching
`[a-z0-9][a-z0-9_.-]{0,39}`). At most one record exists per dimension set per bucket, so:

- polling cannot inflate reliance;
- the data cannot reconstruct who did what at what second;
- a consumer label is self-declared and bounded, never free text and never an identity claim.

## What is never collected

- No IP addresses or user agents in product records. The rate limiter uses a peer address for
  the duration of one request and stores only a hash in a minute-bucketed counter.
- No prompts, tool arguments, tool output, message bodies or span bodies — from any connector.
- No secret values from agent definitions: environment variables, headers and tokens are dropped
  and only their names or digests retained.
- No cross-customer aggregation of security data, for any purpose, including product
  improvement. No model is trained on customer evidence.
- No third-party marketing pixels. The site ships no analytics script at all.

## Feedback comments

The "Was this right?" comment is free text, bounded to 500 characters, written by your own
members. It is tenant data: exportable, erasable, never used for cross-customer analysis.
Control characters are refused at the edge.

## Email and outreach

ThreatVeil sends nothing automatically. Recording interest (`/v1/commercial/interest`), sharing a
passport and applying for an Assurance Launch all record intent and contact nobody; the
responses say so explicitly (`"contacted": false`). Delivery integrations exist but are disabled
unless a deployment enables them.

## Retention

Records follow the plan's retention allowance; raw evidence objects have their own shorter
lifecycle. Export (`docs/DATA_EXPORT.md`) and owner-requested erasure are both available, and
erasure is recorded.
