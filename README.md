# SecAPI — 5 RESTful Cybersecurity APIs

Five FastAPI-based REST services solving common cybersecurity problems. Built
on Python 3.12 + FastAPI + Pydantic. Auto-generated OpenAPI docs at `/docs`.

## Quick start

```bash
cd /home/aj/storage/restful-cybersec
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --port 8000 --reload
```

Docs: http://localhost:8000/docs  ·  Health: http://localhost:8000/health

## The 5 services (19 endpoints)

| # | Service | Prefix | Solves |
|---|---------|--------|--------|
| 1 | Password & breach intelligence | `/api/v1/password-iq` | "Was this password breached?" — k-anonymity HIBP range lookup (only SHA-1 prefix leaves the machine) + local strength scoring |
| 2 | CVE / dependency scanning | `/api/v1/cve-scan` | "Which of my dependencies have known CVEs?" — manifest scan (requirements.txt / package.json), local CVE lookup, live OSV.dev queries |
| 3 | IOC / indicator enrichment | `/api/v1/ioc-enrich` | "Is this hash / IP / URL known-bad?" — hash computation, offline threat-feed enrichment, AbuseIPDB integration |
| 4 | Threat log correlation & alerting | `/api/v1/log-correlate` | "Which log events actually matter?" — event ingestion, rule engine (brute-force, known-bad hash, priv-esc, exfil), alerts API |
| 5 | Document / malware static analysis | `/api/v1/document-analysis` | "Is this PDF/DOC safe to open?" — static macro/URL/email/IP extraction, hashes, risk scoring (never executes payloads) |

### Endpoint quick reference

- **password-iq**: `GET  /strength?password=` · `POST /breach {password}` · `GET /hash/{sha1}`
- **cve-scan**: `GET  /cve/{id}` · `GET /cves?keyword=` · `GET /package/{name}` · `POST /scan` (multipart) · `POST /osv {package, version, ecosystem}`
- **ioc-enrich**: `POST /hashes` (multipart) · `GET /hash/{value}` · `GET /ip/{ip}` · `GET /url?url=`
- **log-correlate**: `POST /ingest` · `POST /ingest/batch` · `GET /events` · `GET /alerts` · `GET /rules`
- **document-analysis**: `POST /analyze` (multipart)

## Tested

**41 tests pass** (29 unit + 12 router integration). Live-verified against real
upstreams:

- HIBP Pwned Passwords: `password123` → confirmed breached, 2,266,543
  occurrences (only the 5-char SHA-1 prefix `CBFDA` was transmitted)
- OSV.dev: requests 2.30.0 → GHSA-9hjg-9r4m-mvj7 (.netrc credential leak) +
  GHSA-9wx4-h78v-vm56 (verify=False session issue)

## Configuration

Environment variables (prefix `SECAPI_`), see `config.py`:

- `SECAPI_ABUSEIPDB_API_KEY` — enable live IP reputation via AbuseIPDB
- `SECAPI_HIBP_RANGE_URL` — override breach source
- `SECAPI_MAX_LOG_BATCH_SIZE` — ingest batch limit
- `SECAPI_EXPECTED_RAPIDAPI_HOST` — when set (e.g. `secapi.p.rapidapi.com`),
  the app returns 403 to any request that does not carry that
  `x-rapidapi-host` header, restricting access to traffic proxied by RapidAPI

## Marketplace deployment (RapidAPI)

This app is ready to deploy behind RapidAPI:

1. Deploy to any public HTTPS host (Render, Railway, Fly.io, AWS, etc.)
   or use `uvicorn main:app` in a container.
2. Register the API on RapidAPI with the OpenAPI spec from `/openapi.json`
   (or `/docs` → download).
3. Never publish the password-iq `/strength` endpoint's plaintext-input
   nature without a note in the description: inputs are checked locally /
   k-anonymously and never stored.

## Layout

```
restful-cybersec/
├── main.py                 # app factory + RapidAPI host gate middleware
├── config.py               # settings
├── requirements.txt
├── apis/
│   ├── password_iq/        # service.py = pure logic, router.py = endpoints
│   ├── cve_scan/
│   ├── ioc_enrich/
│   ├── log_threat/
│   └── document_analysis/
└── tests/                  # 41 tests, one file per service + router integration
```