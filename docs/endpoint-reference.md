# SecAPI — Endpoint Reference

All endpoints live under `/api/v1/<service>`. Base URL (local or your Render
host): `https://secapi.onrender.com/api/v1`.

All responses are JSON. Errors return `{ "detail": ... }` with proper HTTP
codes (400/404/422/502).

---

## 1. Password & Breach Intelligence  — `/password-iq`

### GET /password-iq/strength
Score a password's strength. **Input stays local; nothing is transmitted.**

Query params: `password` (required)

```json
{ "score": 55, "label": "ok", "entropy_bits": 45,
  "checks": ["Minimum length met (>= 8 characters)", "High character variety"],
  "suggestions": [] }
```

### POST /password-iq/breach
k-anonymity breach lookup. Only the first 5 chars of the SHA-1 hash leave
the machine. **Password goes in the body, never the URL.**

Body: `{ "password": "password123" }`
```json
{ "password_provided": true, "hash_prefix": "CBFDA",
  "confirmed_breached": true, "times_seen": 2266543,
  "k_anonymity": "Only CBFDA was transmitted (suffix matched locally)" }
```

### GET /password-iq/hash/{sha1_hex}
Breach count for a full SHA-1 hash you already have.
`sha1_hex` = 40 hex chars. Returns `{ "hash_prefix", "times_seen" }`.

---

## 2. CVE / Dependency Scanning  — `/cve-scan`

### GET /cve-scan/cve/{cve_id}
Look up one CVE. `CVE-2023-30861` → 200 with package/fixed_in/severity/summary.
Unknown CVE → 404.

### GET /cve-scan/cves?keyword=Flask
List known CVEs, optional keyword filter.

### GET /cve-scan/package/{package}
List CVEs affecting a package, e.g. `requests`.

### POST /cve-scan/scan
Upload a manifest (multipart `file`). Accepts `requirements.txt` or
`package.json`. Returns findings with fixed-version and severity.
```json
{ "filename": "req.txt", "total_dependencies_scanned": 2, "vulnerable_count": 1,
  "findings": [{ "package": "flask", "installed": "2.2.0", "fixed_in": "2.3.3",
                 "cve_id": "CVE-2023-30861", "severity": "HIGH", "summary": "..." }] }
```

### POST /cve-scan/osv
Live OSV.dev query. Body: `{ "package", "version", "ecosystem" }`.
```json
{ "package": "requests", "version": "2.30.0", "ecosystem": "PyPI",
  "vulnerabilities": [{ "id": "GHSA-9hjg-9r4m-mvj7", "summary": "...", "modified": "..." }] }
```

---

## 3. IOC / Indicator Enrichment  — `/ioc-enrich`

### POST /ioc-enrich/hashes
Upload a file (multipart `file`) → returns its `md5`, `sha1`, `sha256`.

### GET /ioc-enrich/hash/{value}
Enrich a hash. MD5(32)/SHA1(40)/SHA256(64). Known-bad → `malicious: true`.
```json
{ "value": "44d88612...", "ioc_type": "hash", "malicious": true,
  "confidence": 0.99, "tags": ["bytecode","test","known-bad"],
  "detail": { "matched": { "malware": "eicar_test", "severity": "critical", ... } } }
```

### GET /ioc-enrich/ip/{ip}
Enrich an IP (offline KB, or live AbuseIPDB when a key is configured).
`192.168.1.1` → private/RFC1918. Invalid → 422.

### GET /ioc-enrich/url?url=...
Enrich a URL/domain. Shorteners/known patterns flagged malicious.
`http://bit.ly/xyz123` → `malicious: true`, tag `url-shortener`.

---

## 4. Threat Log Correlation & Alerting  — `/log-correlate`

### POST /log-correlate/ingest
Body: `{ "source": "auth.log", "payload": { "event_type": "authentication",
"success": false, "source_ip": "203.0.113.99" } }`
Returns the alert list (empty if none): `{ "event_id", "alert_count", "alerts" }`.

### POST /log-correlate/ingest/batch
Body: `{ "events": [ { "source": ..., "payload": {...} }, ... ] }`
Max 5000 per batch. Returns `{ "ingested", "total_alerts" }`.

### GET /log-correlate/events
Query ingested events. Filters: `?source=` `?event_type=` `?with_alerts_only=true`
`?limit=` (default 50, max 500).

### GET /log-correlate/alerts
Raised alerts. Filter: `?severity=HIGH`.

### GET /log-correlate/rules
List the 4 active rules.

**Rule engine (alerts fire when an event matches):**
| Rule | Condition |
|---|---|
| R-1001 (HIGH) | >5 failed logins in 60s from same source IP |
| R-1002 (CRITICAL) | event references a known-bad file hash |
| R-1003 (HIGH) | privilege grant/escalation event |
| R-1004 (MEDIUM) | outbound transfer > 100 MB |

---

## 5. Document / Malware Static Analysis  — `/document-analysis`

### POST /document-analysis/analyze
Upload a document (multipart `file`): PDF, Office (doc/docx/xls/xlsx), or
script (js/vbs/hta). **Static analysis only — the payload is never executed.**
```json
{ "filename": "evil.doc", "size_bytes": 78, "file_type": "office",
  "macro_detected": true, "macro_keywords": ["autoopen","sub ","powershell","shell("],
  "urls": ["http://evil.com/payload.exe"], "emails": [], "ips": [],
  "risky_indicators": ["Contains 1 embedded URL(s)"],
  "score": 65,
  "hashes": { "md5": "...", "sha1": "...", "sha256": "..." } }
```
`score` is 0–100 risk. High-macro + exec keywords (powershell, certutil,
mshta, regsvr32, rundll32) push it toward 100.