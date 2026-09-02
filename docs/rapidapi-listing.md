# SecAPI — RapidAPI Listing Copy

Paste-ready content for the RapidAPI "Create API" form.

---

## Basic info

- **API Name**: SecAPI — Cybersecurity Intelligence & Analysis
- **URL slug** (auto): `secapi`
- **Category**: Security
- **URL**: your Render URL, e.g. `https://secapi.onrender.com`

---

## Short description (subtitle)

> Five RESTful security APIs in one: password breach intelligence, CVE /
> dependency scanning, IOC enrichment, log correlation & alerting, and
> document static analysis.

---

## Full description (paste into the description box)

```
Five production-ready REST APIs that solve the most common cybersecurity
pain points — no data leaves your client unnecessarily, everything is
automated and developer-friendly.

WHAT'S INCLUDED

1. Password & Breach Intelligence
   - k-anonymity breach lookup: check if a password has appeared in a known
     breach WITHOUT ever transmitting the full password or hash (only the
     first 5 chars of its SHA-1 are sent). Backed by the real HIBP Pwned
     Passwords dataset.
   - Local password strength scoring (never transmitted or stored).

2. CVE / Dependency Scanning
   - Scan your own requirements.txt / package.json manifests for packages
     with known CVEs.
   - Look up CVEs by ID, list CVEs keyword-filtered, and query Google's live
     OSV.dev database for ecosystem-aware advisories (PyPI, npm, Maven, ...).

3. IOC / Indicator Enrichment
   - Enrich hashes (MD5/SHA1/SHA256), IP addresses, and URLs against threat
     intelligence.
   - Compute hashes of uploaded files on the fly.
   - Optional live AbuseIPDB integration (bring your own API key).

4. Threat Log Correlation & Alerting
   - Ingest security events (single or batch) and get near-real-time alerts
     from a built-in rule engine: brute-force detection, known-bad hashes,
     privilege escalation, and data-exfiltration patterns.
   - Query ingested events and raised alerts.

5. Document / Malware Static Analysis
   - Static (non-executing) triage of suspicious PDFs / Office docs / scripts.
   - Detects embedded macros, PowerShell/VBA trigger keywords, embedded URLs,
     emails, and IPs; computes hashes; outputs a 0-100 risk score — so analysts
     know whether a file is safe to open before opening it.

WHY DEVELOPERS LIKE IT
- Clean, documented OpenAPI spec (/openapi.json)
- Sensitive inputs (passwords) travel in request bodies, never in URLs
- Optional RapidAPI-host gate prevents direct (non-marketplace) abuse
- Stateless, container-friendly, deploys anywhere

SECURITY & PRIVACY
- Passwords are checked k-anonymously and never stored.
- Document analysis never executes payloads (static only).
- Threat-feed data is enriched client-aggregated; bring-your-own-keys for
  live AbuseIPDB lookups.

Note: the bundled local CVE/IOC datasets are curated samples. For the most
current data, use the live OSV.dev queries and the HIBP range API (already
wired in).
```

---

## Recommended tags

`cybersecurity`, `password`, `cve`, `vulnerability`, `ioc`, `threat-intel`,
`log-correlation`, `document-analysis`, `malware`, `security`, `hashing`

---

## Logo

Use a shield / lock monogram. Recommended: a dark "S" or lock glyph on a
security-blue background. (Provide an SVG/PNG in the RapidAPI uploader.)