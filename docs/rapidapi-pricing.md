# SecAPI — Suggested RapidAPI Pricing

Paste-ready pricing tiers for the RapidAPI dashboard. These are starting
points — you can tune them based on the cost of the upstream HIBP/OSV calls
and your free-tier host limits.

---

## Tier 1 — Free (to attract developers)

- **Price**: $0
- **Requests**: 100 / month
- **Note**: good for letting people try the API and leave reviews.

## Tier 2 — Basic

- **Price**: $9 / month
- **Requests**: 10,000 / month
- **Rate**: 10 req / min

## Tier 3 — Pro

- **Price**: $29 / month
- **Requests**: 100,000 / month
- **Rate**: 30 req / min

## Tier 4 — Enterprise / Pay-as-you-go

- **Price**: $99 / month (or contact sales)
- **Requests**: 1,000,000 / month
- **Rate**: 100 req / min

---

## Mix-and-match pricing strategy

Because there are **5 distinct services**, you can either:

**Option A — one API, price by tier** (simplest)
Sell all endpoints under one API. Free tier is tiny; paid tiers widen limits.

**Option B — separate the flagship endpoints** (higher margin)
List the live-data features (breach lookup, OSV queries) as paid, and keep
the pure-local features (password strength, static file hashing, document
analysis) cheap or free. This rewards the endpoints that cost you upstream
HIBP/OSV calls.

---

## Cost guardrails

- HIBP range lookups: free, but rate-limited; **cache the range responses**
  per prefix to cut repeated outbound calls.
- OSV.dev: free, public; fine to use directly.
- AbuseIPDB: **consumes your quota** — only enable when you set
  `SECAPI_ABUSEIPDB_API_KEY`, and consider it a per-call cost driver.

## Recommended starter

- Free: 100 req/mo
- Basic: $9/mo, 10k req
- Pro: $29/mo, 100k req