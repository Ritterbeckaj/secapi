"""Integration tests for the REST layer (endpoint shapes + middleware).

These use FastAPI's TestClient against the full app to lock in the
marketplace-facing contract: response codes, body shapes, and RapidAPI-gate
behaviour.
"""
import os

import pytest
from fastapi.testclient import TestClient

from main import app
from config import settings

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_password_strength_validation():
    assert client.get("/api/v1/password-iq/strength").status_code == 422
    assert client.get("/api/v1/password-iq/strength?password=").status_code == 422
    r = client.get("/api/v1/password-iq/strength?password=Tr0ub4dor&3")
    assert r.status_code == 200
    assert "score" in r.json()


def test_breach_is_post_with_body():
    # Password must travel in the body, never in the URL path
    r = client.post("/api/v1/password-iq/breach",
                    json={"password": "password123"})
    assert r.status_code == 200
    assert r.json()["confirmed_breached"] is True
    # The URL-path variant of this endpoint no longer exists at all
    assert client.get("/api/v1/password-iq/breach/password123").status_code == 404


def test_hash_lookup_path_param():
    sha1_pw = "CBFDAC6008F9CAB4083784CBD1874F76618D2A97"
    r = client.get(f"/api/v1/password-iq/hash/{sha1_pw}")
    assert r.status_code == 200
    assert r.json()["times_seen"] > 0
    assert client.get("/api/v1/password-iq/hash/zzz").status_code == 422


def test_cve_lookup_404():
    assert client.get("/api/v1/cve-scan/cve/CVE-2024-99999").status_code == 404


def test_osv_is_post_with_json_body():
    r = client.post("/api/v1/cve-scan/osv",
                    json={"package": "requests", "version": "2.30.0",
                          "ecosystem": "PyPI"})
    assert r.status_code == 200
    assert isinstance(r.json()["vulnerabilities"], list)
    # Bare GET with query params must not be the contract
    assert client.get("/api/v1/cve-scan/osv?package=requests&version=2.30.0").status_code == 405


def test_manifest_scan_upload():
    r = client.post("/api/v1/cve-scan/scan",
                    files={"file": ("req.txt", b"Flask==2.2.0\n", "text/plain")})
    assert r.status_code == 200
    assert r.json()["vulnerable_count"] == 1


def test_ioc_enrich():
    assert client.get("/api/v1/ioc-enrich/ip/192.168.1.1").status_code == 200
    assert client.get("/api/v1/ioc-enrich/ip/999.1.1.1").status_code == 422
    assert client.get("/api/v1/ioc-enrich/hash/zzz").status_code == 422


def test_log_ingest_and_alerts():
    r = client.post("/api/v1/log-correlate/ingest",
                    json={"source": "test", "payload": {"event_type": "privilege",
                                                        "action": "grant"}})
    assert r.status_code == 200
    assert r.json()["alert_count"] >= 1
    assert client.get("/api/v1/log-correlate/alerts").status_code == 200


def test_document_analysis_upload():
    r = client.post("/api/v1/document-analysis/analyze",
                    files={"file": ("m.doc", b"Sub AutoOpen()\r\nShell(\"powershell -enc x\")\r\nEnd Sub",
                                    "application/msword")})
    assert r.status_code == 200
    data = r.json()
    assert data["macro_detected"] is True
    assert data["score"] >= 40


def test_document_analysis_without_file():
    assert client.post("/api/v1/document-analysis/analyze").status_code == 422


def test_rapidapi_gate_enforced():
    original = settings.expected_rapidapi_host
    settings.expected_rapidapi_host = "secapi.p.rapidapi.com"
    try:
        g = TestClient(app)
        # Without the RapidAPI host header -> 403
        assert g.get("/health").status_code == 403
        # With the marketplace host header -> allowed
        r = g.get("/health", headers={"x-rapidapi-host": "secapi.p.rapidapi.com"})
        assert r.status_code == 200
    finally:
        settings.expected_rapidapi_host = original