"""Threat log correlation & alerting service.

Solves the common SOC problem: "I have a flood of security logs, but which
events actually matter?" Instead of hunting manually, this service ingests
events, runs them through a rule engine, and emits alerts when they correlate
with known bad indicators or policy violations.

A simple in-memory store backs the demo; swap the repository for a real
time-series backend (Elasticsearch/ClickHouse) in production.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any

# ---------------------------------------------------------------------------
# Rule engine
# ---------------------------------------------------------------------------

# Rules are ordered; the first matching rule raises an alert.
RULES: list[dict[str, Any]] = [
    {
        "id": "R-1001",
        "name": "Multiple failed logins",
        "severity": "HIGH",
        "description": "More than 5 failed authentication attempts within 60s from same source IP.",
        "matcher": lambda ev: (
            ev.get("event_type") == "authentication" and
            ev.get("success") is False and
            _recent_failures(ev.get("source_ip"), window=60) >= 5
        ),
    },
    {
        "id": "R-1002",
        "name": "Known-bad hash observed",
        "severity": "CRITICAL",
        "description": "Event references an IOC hash present in the threat feed.",
        "matcher": lambda ev: _hash_is_bad(ev.get("file_hash")),
    },
    {
        "id": "R-1003",
        "name": "Privilege escalation detected",
        "severity": "HIGH",
        "description": "User gained administrative/root privileges unexpectedly.",
        "matcher": lambda ev: (
            ev.get("event_type") == "privilege" and
            ev.get("action") in ("grant", "escalate")
        ),
    },
    {
        "id": "R-1004",
        "name": "Outbound exfiltration pattern",
        "severity": "MEDIUM",
        "description": "Large outbound transfer flagged as unusual.",
        "matcher": lambda ev: (
            ev.get("event_type") == "network" and
            (ev.get("direction") == "outbound") and
            (ev.get("bytes") or 0) > 100_000_000
        ),
    },
]

# In-memory event ledger for correlation helpers
_EVENT_LEDGER: list[dict[str, Any]] = []
_FAILURES_BY_IP: dict[str, list[float]] = {}


def _recent_failures(source_ip: str | None, window: int = 60) -> int:
    if not source_ip:
        return 0
    now = time.time()
    recent = [t for t in _FAILURES_BY_IP.get(source_ip, []) if now - t <= window]
    _FAILURES_BY_IP[source_ip] = recent
    return len(recent)


def _hash_is_bad(file_hash: str | None) -> bool:
    if not file_hash:
        return False
    from apis.ioc_enrich.service import KNOWN_BAD_HASHES
    return file_hash.lower() in KNOWN_BAD_HASHES


@dataclass
class Event:
    id: str
    timestamp: float
    source: str
    payload: dict[str, Any]
    alerts: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def ingest_event(source: str, payload: dict[str, Any]) -> Event:
    ev = Event(id=uuid.uuid4().hex, timestamp=time.time(),
               source=source, payload=payload)

    if payload.get("event_type") == "authentication" and payload.get("success") is False:
        ip = payload.get("source_ip")
        if ip:
            _FAILURES_BY_IP.setdefault(ip, []).append(time.time())

    _EVENT_LEDGER.append(ev)

    for rule in RULES:
        try:
            if rule["matcher"](payload):
                ev.alerts.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "description": rule["description"],
                    "triggered_at": time.time(),
                })
        except Exception:
            continue  # a bad event shouldn't crash the pipeline

    return ev
