"""Document / malware static analysis service.

Solves the common problem: "I got a suspicious PDF/DOC/XLS — is it safe to
open?" This service performs *static* (non-executing) triage of office/pdfs:

  * Detect and flag embedded macros (VBA / Auto* keywords, OLE 'Mso' streams).
  * Extract embedded URLs and file hashes for further enrichment.
  * Compute hashes and surface risky characteristics (encrypted, obfuscated,
    auto-execute keywords) so analysts can decide before opening anything.

All analysis is heuristic and does NOT execute/desanitize the payload.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, asdict

URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

MACRO_TRIGGERS = [
    "autoopen", "autoclose", "autoexec", "document_open", "workbook_open",
    "worksheet_activate", "sub ", "function ", "vba", "mso-", "powershell",
    "cmd.exe", "shell(", "wscript", "cscript", "regsvr32", "rundll32",
    "certutil", "mshta", "$env:", "invoke-expression", "winword", "excel",
]

OLE_SPECIAL = {b"\\x00M\\x00s\\x00o\\x00": "OLE Compound (Mso) stream",
               b"MZ": "PE header (executable embedded)",
               b"PK": "ZIP/Office compound",
               b"%PDF": "PDF document"}


@dataclass
class Analysis:
    filename: str
    size_bytes: int
    file_type: str
    hashes: dict[str, str]
    macro_detected: bool
    macro_keywords: list[str]
    urls: list[str]
    emails: list[str]
    ips: list[str]
    risky_indicators: list[str]
    score: int  # 0..100 risk score

    def to_dict(self) -> dict:
        return asdict(self)


def detect_type(raw: bytes, filename: str) -> str:
    if raw.startswith(b"%PDF"):
        return "pdf"
    if raw.startswith(b"PK"):
        return "office/zip"
    if b"\\x00\\x00\\x00Microsoft" in raw or raw.startswith(b"\\xD0\\xCF\\x11\\xE0"):
        return "ole"
    ext = (filename or "").lower()
    if ext.endswith((".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx")):
        return "office"
    if ext.endswith((".js", ".vbs", ".hta")):
        return "script"
    return "unknown"


def _decodable_text(raw: bytes) -> str:
    """Decode latin-1 plus UTF-16 only when the bytes resemble UTF-16 (null-byte spaced)."""
    text = raw.decode("latin-1", errors="ignore")
    # Cheap UTF-16 heuristic: significant proportion of alternating null bytes
    pairs = len(raw) // 2
    if pairs:
        evens = raw[0::2]
        odds = raw[1::2]
        nulls = (evens.count(0) + odds.count(0))
        if nulls / max(len(raw), 1) > 0.3:
            text += "\n" + raw.decode("utf-16-le", errors="ignore")
    return text


def analyze_document(filename: str, raw: bytes) -> Analysis:
    text = _decodable_text(raw)

    urls = list(dict.fromkeys(URL_RE.findall(text)))
    emails = list(dict.fromkeys(EMAIL_RE.findall(text)))
    ips = list(dict.fromkeys(IPV4_RE.findall(text)))
    # filter clearly-fake IPs
    ips = [i for i in ips if not all(int(o) < 10 for o in i.split("."))]

    macro_keywords = list(dict.fromkeys(
        kw for kw in MACRO_TRIGGERS if re.search(rf"\b{re.escape(kw)}", text.lower())
    ))

    risky: list[str] = []
    # OLE special markers
    for marker, label in OLE_SPECIAL.items():
        if marker in raw:
            risky.append(label)

    if urls:
        risky.append(f"Contains {len(urls)} embedded URL(s)")
    if emails:
        risky.append(f"Contains {len(emails)} email address(es)")
    if any(s in text.lower() for s in ("encrypted", "protected", "obfuscated")):
        risky.append("May be encrypted/obfuscated")
    if raw.startswith(b"%PDF") and b"/OpenAction" in raw:
        risky.append("PDF /OpenAction auto-action present")

    file_type = detect_type(raw, filename)
    macro_detected = bool(macro_keywords)

    hashes = {
        "md5": hashlib.md5(raw).hexdigest(),  # noqa: S324
        "sha1": hashlib.sha1(raw).hexdigest(),  # noqa: S324
        "sha256": hashlib.sha256(raw).hexdigest(),
    }

    # Risk scoring heuristic
    score = 5 if len(raw) > 10_000_000 else 0
    if macro_detected:
        score += 40
    if any(k in macro_keywords for k in ("powershell", "cmd.exe", "certutil",
                                         "mshta", "regsvr32", "rundll32", "invoke-expression")):
        score += 20
    score += min(len(urls) * 5, 20)
    if "PE header" in risky:
        score += 20
    score = min(100, score)

    return Analysis(filename=filename, size_bytes=len(raw), file_type=file_type,
                    hashes=hashes, macro_detected=macro_detected,
                    macro_keywords=macro_keywords, urls=urls, emails=emails,
                    ips=ips, risky_indicators=risky, score=score)
