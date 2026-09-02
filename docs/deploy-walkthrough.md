# SecAPI — Render + RapidAPI Deployment Walkthrough

This is the **manual, dashboard-based** path. Render has no CLI and no headless
deploy API, so deployment happens through the web dashboard after you connect
your GitHub account.

Estimated time: 15–20 minutes. You'll need accounts at render.com and
rapidapi.com.

---

## Part A — Deploy on Render (free tier)

1. Go to https://dashboard.render.com/select-repo?type=web
2. Log in. If prompted, **authorize** Render to read your GitHub account.
3. You'll be in "New Web Service". If Render suggests "Blueprint", **cancel
   it** and use **New → Web Service** instead (simplest and fully controlled).
4. Pick the repository **Ritterbeckaj/secapi**.
5. Render auto-detects the `render.yaml` file. It will prefill the service
   settings. Confirm:
   - **Name**: `secapi`
   - **Region**: any (us-east is fine)
   - **Runtime / Environment**: Docker (from the Dockerfile)
   - **Plan**: Free
   - **Health Check Path**: `/health`  ← make sure this is set
6. Expand **Environment** and set:
   - `SECAPI_EXPECTED_RAPIDAPI_HOST`: leave **empty for now** (set it after
     RapidAPI gives you a proxy host — otherwise everything 403s during
     testing).
   - `SECAPI_ABUSEIPDB_API_KEY`: leave empty unless you have an AbuseIPDB key.
7. Click **Create Web Service**.
8. Wait ~2–4 minutes for the Docker build + deploy. Watch the logs in the
   Render dashboard — you should see uvicorn start and your healthcheck pass.
9. When the build finishes, Render gives you a URL like:
   `https://secapi.onrender.com`
10. Verify:
    - `https://secapi.onrender.com/health` → `{"status":"ok","version":"v1"}`
    - `https://secapi.onrender.com/docs` → interactive Swagger UI (this is
      your auto-generated documentation!)
    - `https://secapi.onrender.com/openapi.json` → the spec you'll give RapidAPI

> Free-tier Render web services sleep after ~15 min of no traffic and wake on
> the next request (first call after idle takes a few seconds). This is fine
> for a free API tier. Upgrade the plan if you need always-on.

---

## Part B — Register on RapidAPI

1. Go to https://rapidapi.com and sign up / log in.
2. Top-right: **My APIs → Add New API**.
3. **Security mode**: RapidAPI Proxy (recommended) — RapidAPI forwards calls
   to your Render URL on the consumer's behalf.
4. Provide the base URL: `https://secapi.onrender.com`
5. Copy/paste the listing copy from `docs/rapidapi-listing.md`.
6. **Import the spec**: RapidAPI has an "Import from OpenAPI" option. Use
   `docs/secapi-openapi.json` (already exported from the app). This adds all
   19 endpoints with params automatically.
7. Set the pricing tiers from `docs/rapidapi-pricing.md`.
8. Publish the API (it starts private until you make it public).

After publishing, RapidAPI shows you your **proxy host**, typically:
`secapi.p.rapidapi.com`

---

## Part C — Lock it down (final step)

Once the RapidAPI API is published and you have the proxy host:

1. Go back to Render → your `secapi` service → **Environment**.
2. Set `SECAPI_EXPECTED_RAPIDAPI_HOST` = `secapi.p.rapidapi.com`
   (the exact proxy host from your RapidAPI dashboard).
3. Redeploy.
4. Verify: a direct curl to
   `https://secapi.onrender.com/health` (no RapidAPI headers) now returns
   **403**, while calls through RapidAPI (which inject `x-rapidapi-host`)
   succeed.

This ensures only paid RapidAPI consumers can use the API, and nobody can
bypass the marketplace to hit your Render URL for free.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Deploy fails at Docker build | Check Render logs; ensure `requirements.txt` resolves. FastAPI 0.115.x + python:3.12-slim is fine. |
| Everything returns 403 after going live | You set `SECAPI_EXPECTED_RAPIDAPI_HOST` too early or to the wrong value. It must exactly match RapidAPI's proxy host. |
| First request is slow | Free-tier Render sleep/wake. Expected. |
| /openapi.json 404 | The app must be running; check /health first. |
| Breach/OSV endpoints return 502 | Outbound egress works on Render, but HIBP/OSV may be rate-limiting or unreachable from the region — retry, or check the host allows HTTPS egress. |