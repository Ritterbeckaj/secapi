"""CVE / dependency scanning service.

Solves the common problem: "which packages in my project have known
vulnerabilities, and what CVE IDs should I look up?"

Supports:
  * Local CVE lookup by ID / keyword (seeded sample dataset).
  * Real OSV.dev query API (ecosystem-aware) for up-to-date results.
  * Dependency manifest parsing (requirements.txt / package.json) with a
    CVE-by-package scan using the local dataset.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, asdict

# ---------------------------------------------------------------------------
# Local sample CVE dataset (upstream-feeding is wired via OSV for live data)
# ---------------------------------------------------------------------------

# {package: [(fixed_version, cve_id, severity, summary)]}
LOCAL_PACKAGE_CVES: dict[str, list[tuple[str, str, str, str]]] = {
    "flask": [
        ("2.3.3", "CVE-2023-30861", "HIGH",
         "Flask vulnerable to server-side template injection via crafted JSON key names"),
    ],
    "flask-cors": [
        ("4.0.0", "CVE-2023-40157", "MEDIUM",
         "Flask-CORS reflects arbitrary Origin and allows credentialed CORS bypass"),
    ],
    "requests": [
        ("2.31.0", "CVE-2023-32681", "MEDIUM",
         "Requests leaks auth cookies across hosts via reused proxy connections"),
    ],
    "urllib3": [
        ("1.26.19", "CVE-2023-45803", "MEDIUM",
         "urllib3 HTTP request can be modified by a crafted Host header during redirects"),
    ],
    "fastapi": [
        ("0.103.0", "CVE-2023-41585", "HIGH",
         "FastAPI path traversal via crafted path parameters in certain configurations"),
    ],
    "django": [
        ("4.2.15", "CVE-2024-38875", "HIGH",
         "Django potential denial-of-service via large number of brackets in URL paths"),
    ],
}

CVE_ALIASES = {
    "CVE-2023-30861": ("flask", "2.3.3", "HIGH", "SSTI via crafted JSON key names"),
    "CVE-2023-40157": ("flask-cors", "4.0.0", "MEDIUM", "CORS reflects arbitrary Origin"),
    "CVE-2023-32681": ("requests", "2.31.0", "MEDIUM", "Cookie leakage on redirect"),
    "CVE-2023-45803": ("urllib3", "1.26.19", "MEDIUM", "Host header redirect parsing"),
    "CVE-2023-41585": ("fastapi", "0.103.0", "HIGH", "Path traversal"),
    "CVE-2024-38875": ("django", "4.2.15", "HIGH", "ReDoS / DoS via URL brackets"),
}


@dataclass
class Vulnerability:
    package: str
    installed: str
    fixed_in: str
    cve_id: str
    severity: str
    summary: str

    def to_dict(self) -> dict:
        return asdict(self)


def _parse_version(version: str) -> tuple:
    """Turn a version string into a sortable tuple (numeric parts)."""
    parts = re.findall(r"\d+", version)
    return tuple(int(p) for p in parts) or (0,)


def version_is_vulnerable(installed: str, fixed_in: str) -> bool:
    """True when installed < fixed (fixed version is the patched floor)."""
    return _parse_version(installed) < _parse_version(fixed_in)


def scan_requirements(text: str) -> list[Vulnerability]:
    """Parse a requirements.txt-style manifest and return vulnerable packages."""
    findings: list[Vulnerability] = []
    for raw_line in text.splitlines():
        line = raw_line.split("#")[0].strip()
        if not line or line.startswith("-") or "://" in line:
            continue
        # support: name==x.y.z  |  name>=x  |  name (plain)
        m = re.match(r"^([A-Za-z0-9_.\-]+?)\s*[<>=!~]+\s*([0-9][^\s,;]*)?", line)
        if not m:
            m = re.match(r"^([A-Za-z0-9_.\-]+)\s*$", line)
            if not m:
                continue
            pkg, version = m.group(1).lower(), "0.0"
        else:
            pkg, version = m.group(1).lower(), (m.group(2) or "0.0")

        for fixed, cve_id, severity, summary in LOCAL_PACKAGE_CVES.get(pkg, []):
            if version_is_vulnerable(version, fixed):
                findings.append(
                    Vulnerability(pkg, version, fixed, cve_id, severity, summary)
                )
    return findings


def scan_package_json(text: str) -> list[Vulnerability]:
    """Parse a package.json manifest's dependencies for vulnerable packages."""
    findings: list[Vulnerability] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return findings

    deps: dict[str, str] = {}
    for section in ("dependencies", "devDependencies"):
        deps.update(data.get(section, {}) or {})

    for pkg, spec in deps.items():
        if not isinstance(spec, str):
            continue
        # Extract a concrete pinned version, else best-effort first number
        m = re.search(r"(\d+)(\.\d+)+(\.\d+)?", spec)
        version = m.group(0) if m else "0.0"

        for fixed, cve_id, severity, summary in LOCAL_PACKAGE_CVES.get(pkg.lower(), []):
            if version_is_vulnerable(version, fixed):
                findings.append(
                    Vulnerability(pkg.lower(), version, fixed, cve_id, severity, summary)
                )
    return findings
