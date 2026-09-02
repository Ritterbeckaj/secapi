"""Composable FastAPI application exposing all five security REST services.

Run with:
    uvicorn main:app --reload --port 8000

Interactive OpenAPI docs:  http://localhost:8000/docs
Each service lives under /api/v1/<service>.
"""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config import settings
from apis.password_iq.router import router as password_router
from apis.cve_scan.router import router as cve_router
from apis.ioc_enrich.router import router as ioc_router
from apis.log_threat.router import router as log_router
from apis.document_analysis.router import router as doc_router

app = FastAPI(
    title=settings.app_name,
    version=settings.api_version,
    description=(
        "Five RESTful APIs that solve common cybersecurity problems:\n"
        "1. Password & breach intelligence\n"
        "2. CVE / dependency scanning\n"
        "3. IOC / indicator enrichment\n"
        "4. Threat log correlation & alerting\n"
        "5. Document / malware static analysis"
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def rapidapi_host_check(request: Request, call_next):
    """Reject direct calls when deployed behind RapidAPI.

    RapidAPI routes traffic through your marketplace host (e.g.
    'secapi.p.rapidapi.com') and injects x-rapidapi-host as a hint of the
    intended endpoint. When EXPECTED_RAPIDAPI_HOST is configured, requests
    that don't present that host header are refused, so only paying
    marketplace consumers (proxied by RapidAPI) can use the API.
    """
    expected = settings.expected_rapidapi_host
    if not expected:
        return await call_next(request)
    if request.headers.get("x-rapidapi-host") != expected:
        return JSONResponse(
            status_code=403,
            content={"detail": "This API is served exclusively through RapidAPI."},
        )
    return await call_next(request)

API_PREFIX = f"/api/{settings.api_version}"

_services = [
    ("password-iq", password_router, "Password & breach intelligence"),
    ("cve-scan", cve_router, "CVE / dependency scanning"),
    ("ioc-enrich", ioc_router, "IOC / indicator enrichment"),
    ("log-correlate", log_router, "Threat log correlation & alerting"),
    ("document-analysis", doc_router, "Document / malware static analysis"),
]

for path, router, _label in _services:
    app.include_router(router, prefix=f"{API_PREFIX}/{path}", tags=[path])

_SERVICE_TABLE = "\n".join(
    f"* `{API_PREFIX}/{path}` — {label}" for path, _, label in _services
)


@app.get("/", include_in_schema=False)
def root() -> dict:
    return {
        "service": settings.app_name,
        "docs": "/docs",
        "health": "/health",
        "services": _SERVICE_TABLE,
    }


@app.get("/health", tags=["meta"])
def health() -> dict:
    return {"status": "ok", "version": settings.api_version}
