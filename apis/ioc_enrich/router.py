"""REST endpoints for IOC / indicator enrichment."""
from __future__ import annotations

import aiohttp

from fastapi import APIRouter, HTTPException, UploadFile, File, Query

from config import settings
from .service import (
    compute_hashes,
    enrich_hash,
    enrich_ip,
    enrich_url,
)

router = APIRouter()


@router.post("/hashes", summary="Compute MD5/SHA1/SHA256 of an uploaded file")
async def file_hashes(file: UploadFile = File(...)) -> dict:
    data = await file.read()
    return {
        "filename": file.filename,
        "size_bytes": len(data),
        **compute_hashes(data),
    }


@router.get("/hash/{value}", summary="Enrich a hash against the threat feed")
def hash_enrich(value: str) -> dict:
    try:
        result = enrich_hash(value)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return result.to_dict()


@router.get("/ip/{ip}", summary="Enrich an IP address (offline KB or AbuseIPDB)")
async def ip_enrich(ip: str) -> dict:
    if settings.abuseipdb_api_key:
        return await _abuseipdb_lookup(ip)
    try:
        result = enrich_ip(ip)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return result.to_dict()


@router.get("/url", summary="Enrich a URL / domain")
def url_enrich(url: str = Query(..., description="URL or domain to enrich")) -> dict:
    try:
        result = enrich_url(url)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return result.to_dict()


async def _abuseipdb_lookup(ip: str) -> dict:
    headers = {"Key": settings.abuseipdb_api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": "true"}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(settings.abuseipdb_check_url, headers=headers,
                                   params=params, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    d = data.get("data", {})
                    return {
                        "value": ip, "ioc_type": "ip", "malicious": d.get("abuseConfidenceScore", 0) > 50,
                        "confidence": d.get("abuseConfidenceScore", 0) / 100.0,
                        "tags": ["ip", "abuseipdb"], "detail": d,
                    }
                raise HTTPException(502, f"AbuseIPDB returned HTTP {resp.status}")
    except aiohttp.ClientError as exc:
        raise HTTPException(502, f"AbuseIPDB request failed: {exc}") from exc
