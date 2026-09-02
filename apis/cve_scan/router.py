"""REST endpoints for CVE / dependency scanning."""
from __future__ import annotations

import aiohttp

from fastapi import APIRouter, HTTPException, Query, UploadFile, File
from pydantic import BaseModel, Field

from .service import (
    CVE_ALIASES,
    LOCAL_PACKAGE_CVES,
    scan_requirements,
    scan_package_json,
)

router = APIRouter()

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


@router.get("/cve/{cve_id}", summary="Look up a single CVE by ID")
def get_cve(cve_id: str) -> dict:
    cve_id = cve_id.upper()
    if cve_id in CVE_ALIASES:
        pkg, fixed, severity, summary = CVE_ALIASES[cve_id]
        return {"cve_id": cve_id, "package": pkg, "fixed_in": fixed,
                "severity": severity, "summary": summary, "source": "local"}
    raise HTTPException(404, f"Unknown CVE: {cve_id}")


@router.get("/cves", summary="List known CVEs, optionally filtered by keyword")
def list_cves(keyword: str | None = None) -> list[dict]:
    out = []
    for cve_id, (pkg, fixed, severity, summary) in CVE_ALIASES.items():
        entry = {"cve_id": cve_id, "package": pkg, "fixed_in": fixed,
                 "severity": severity, "summary": summary}
        if keyword and keyword.lower() not in f"{cve_id} {pkg} {summary}".lower():
            continue
        out.append(entry)
    return out


@router.get("/package/{package}", summary="List CVEs affecting a package")
def package_cves(package: str) -> list[dict]:
    pkg = package.lower()
    return [
        {"package": pkg, "fixed_in": fixed, "cve_id": cve_id,
         "severity": severity, "summary": summary}
        for fixed, cve_id, severity, summary in LOCAL_PACKAGE_CVES.get(pkg, [])
    ]


@router.post("/scan", summary="Scan an uploaded dependency manifest for known CVEs")
async def scan_manifest(file: UploadFile = File(...)) -> dict:
    raw = await file.read()
    text = raw.decode("utf-8", errors="replace")
    name = (file.filename or "").lower()

    if name.endswith(".json") or "package.json" in name:
        findings = scan_package_json(text)
    else:
        findings = scan_requirements(text)

    return {
        "filename": file.filename,
        "total_dependencies_scanned": _count_manifest(text, name),
        "findings": [f.to_dict() for f in findings],
        "vulnerable_count": len(findings),
    }


class OSVQueryIn(BaseModel):
    package: str = Field(..., description="Package name, e.g. 'requests'")
    version: str = Field(..., description="Version, e.g. '2.30.0'")
    ecosystem: str = Field("PyPI", description="Ecosystem, e.g. PyPI, npm, Maven")


@router.post("/osv", summary="Query the live OSV.dev database for a package/version")
async def osv_query(body: OSVQueryIn) -> dict:
    """Live vulnerability query against OSV.dev (Google). Returns raw advisories."""
    package, version, ecosystem = body.package, body.version, body.ecosystem
    payload = {"package": {"name": package, "ecosystem": ecosystem}, "version": version}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(OSV_QUERY_URL, json=payload,
                                    timeout=aiohttp.ClientTimeout(total=20)) as resp:
                if resp.status == 404:
                    return {"package": package, "version": version, "vulnerabilities": []}
                if resp.status != 200:
                    raise HTTPException(502, f"OSV returned HTTP {resp.status}")
                data = await resp.json()
    except aiohttp.ClientError as exc:
        raise HTTPException(502, f"OSV request failed: {exc}") from exc

    vulns = [{"id": v.get("id"), "summary": v.get("summary"),
              "modified": v.get("modified")}
             for v in data.get("vulns", [])]
    return {"package": package, "version": version, "ecosystem": ecosystem,
            "vulnerabilities": vulns}


def _count_manifest(text: str, name: str) -> int:
    if name.endswith(".json") or "package.json" in name:
        import json
        try:
            data = json.loads(text)
            return len((data.get("dependencies") or {})) + len(
                (data.get("devDependencies") or {}))
        except json.JSONDecodeError:
            return 0
    count = 0
    for raw_line in text.splitlines():
        line = raw_line.split("#")[0].strip()
        if line and not line.startswith("-"):
            count += 1
    return count
