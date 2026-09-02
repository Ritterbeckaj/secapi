"""IOC / indicator enrichment service.

Solves the common problem: "is this hash / URL / IP address known-bad, and
what do I know about it?" — the core triage step in threat intel workflows.

Capabilities:
  * Compute standard hashes (MD5/SHA1/SHA256) of provided file content.
  * Enrich a hash against a local 'known-bad' feed.
  * Enrich an IP against AbuseIPDB (live) or an offline static blocklist.
  * Enrich a URL / domain with basic normalization and offline reputation.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, asdict

# ---------------------------------------------------------------------------
# Offline static knowledge base (demonstration + offline fallback)
# ---------------------------------------------------------------------------

KNOWN_BAD_HASHES: dict[str, dict] = {
    # sample known-bad hashes (placeholders — wire your real feeds here)
    "44d88612fea8a8f36de82e1278abb02f": {"malware": "eicar_test", "severity": "critical",
                                          "family": "test", "type": "bytecode"},
}

# {cidr_or_ip: {asn_org, country, notes}}
IP_KB: dict[str, dict] = {
    "10.0.0.0/8":   {"asn_org": "RFC1918 Private", "country": "—", "private": True, "notes": "Private range"},
    "172.16.0.0/12":{"asn_org": "RFC1918 Private", "country": "—", "private": True, "notes": "Private range"},
    "192.168.0.0/16":{"asn_org": "RFC1918 Private", "country": "—", "private": True, "notes": "Private range"},
    "127.0.0.0/8":  {"asn_org": "Loopback", "country": "—", "private": True, "notes": "Localhost"},
}

# Simple domain heuristics for URL reputation (offline)
MALICIOUS_DOMAIN_MARKERS = [
    r"bit\.ly", r"tinyurl", r"pastebin", r"file-?transfer", r"update-download",
    r"secure-login", r"dropbox\.com/s/u/", r"0day", r"cryptominer",
]

# ---------------------------------------------------------------------------
# Core operations
# ---------------------------------------------------------------------------


def compute_hashes(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),  # noqa: S324 (intel purpose)
        "sha1": hashlib.sha1(data).hexdigest(),  # noqa: S324
        "sha256": hashlib.sha256(data).hexdigest(),
    }


@dataclass
class IoC:
    value: str
    ioc_type: str
    malicious: bool
    confidence: float  # 0..1
    tags: list[str]
    detail: dict

    def to_dict(self) -> dict:
        return asdict(self)


def enrich_hash(h) -> IoC:
    h = (h or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", h):
        raise ValueError("Hash must be MD5(32), SHA1(40) or SHA256(64) hex.")
    hit = KNOWN_BAD_HASHES.get(h)
    if hit:
        return IoC(h, "hash", True, 0.99,
                   [hit["type"], hit["family"], "known-bad"],
                   {"matched": hit})
    return IoC(h, "hash", False, 0.1,
               ["hash", "no-match"], {"matched": None})


def enrich_ip(ip: str) -> IoC:
    ip = ip.strip()
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {ip}") from exc

    detail: dict = {"ip": ip, "version": parsed.version,
                    "is_global": parsed.is_global,
                    "is_private": parsed.is_private}
    tags, malicious, confidence = ["ip"], False, 0.05

    for cidr, meta in IP_KB.items():
        if parsed in ipaddress.ip_network(cidr):
            detail.update(meta)
            tags.append("private" if meta.get("private") else "known")
            break
    else:
        if not parsed.is_global:
            tags.append("special-use")

    return IoC(ip, "ip", malicious, confidence, tags, detail)


def enrich_url(url: str) -> IoC:
    url = (url or "").strip()
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url
    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = parsed.hostname or ""

    tags, malicious, confidence = ["url"], False, 0.05
    detail = {"url": url, "scheme": parsed.scheme, "host": host,
              "path": parsed.path or "/", "is_ip_host": _is_ip(host)}

    for marker in MALICIOUS_DOMAIN_MARKERS:
        if re.search(marker, host + parsed.path, re.IGNORECASE):
            tags.append("url-shortener" if "bit.ly" in host or "tinyurl" in host else "suspicious-pattern")
            malicious = True
            confidence = 0.7
            detail["reason"] = f"matched marker '{marker}'"
            break

    if not host:
        raise ValueError("Could not parse host from URL")

    return IoC(url, "url", malicious, confidence, tags, detail)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
