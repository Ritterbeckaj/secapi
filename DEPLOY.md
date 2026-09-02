# Deploying SecAPI

The app is a standard FastAPI service with no external state (the log store is
in-memory), so it deploys anywhere that can run a container or a Python
process:

- Render (free tier) — `render.yaml` included
- Railway / Fly.io — point at the same `uvicorn main:app` command
- Any VPS — `docker compose up -d`
- AWS/GCP — container registry or a plain VM

## Local / VPS

```bash
docker compose up -d --build
curl http://localhost:8000/health
```

## Render (free tier, most common for API marketplaces)

1. Push this repo to GitHub (public).
2. In Render: **New → Web Service → connect the repo**.
3. Render will detect `render.yaml` (Blueprint) — or set manually:
   - Build command: (none — Dockerfile auto-detected) or `pip install -r requirements.txt`
   - Start command: `uvicorn main:app --host 0.0.0.0 --port 8000`
4. Add the env vars from `docker-compose.yml` (at minimum set
   `SECAPI_EXPECTED_RAPIDAPI_HOST` to your future RapidAPI host once the API
   is registered).
5. Deploy → you get `https://<name>.onrender.com`.

## After it's live

1. Download the OpenAPI spec: `https://<host>/openapi.json`.
2. Register on **RapidAPI**: New API → `Upload API` via the spec.
3. Set `SECAPI_EXPECTED_RAPIDAPI_HOST` to RapidAPI's proxy host (shown in
   your RapidAPI dashboard, e.g. `secapi.p.rapidapi.com`) and redeploy —
   requests that bypass RapidAPI then get 403.

## Deploy notes

- In-memory log store resets on restart (single instance is fine; add a DB
  if you need durable log correlation at scale).
- `--workers 2` in the Dockerfile is fine for the free tier; the app is
  stateless so you can scale horizontally.
- HIBP range lookups and OSV queries go outbound to the internet — the host
  must allow egress HTTPS.