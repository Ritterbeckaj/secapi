"""REST endpoints for Threat log correlation & alerting."""
from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from config import settings
from .service import ingest_event, _EVENT_LEDGER, RULES

router = APIRouter()


class EventIn(BaseModel):
    source: str = Field(..., description="Log source, e.g. 'auth.log' or 'ids'")
    payload: dict[str, Any] = Field(..., description="Structured event fields")


class BatchIn(BaseModel):
    events: list[EventIn]


@router.post("/ingest", summary="Ingest a single event and run correlation rules")
def ingest(event: EventIn) -> dict:
    result = ingest_event(event.source, event.payload)
    return {"event_id": result.id, "alert_count": len(result.alerts),
            "alerts": result.alerts}


@router.post("/ingest/batch", summary="Ingest a batch of events (bulk upload)")
def ingest_batch(batch: BatchIn) -> dict:
    if len(batch.events) > settings.max_log_batch_size:
        raise HTTPException(422, f"Batch too large (max {settings.max_log_batch_size})")
    total_alerts = 0
    for ev in batch.events:
        result = ingest_event(ev.source, ev.payload)
        total_alerts += len(result.alerts)
    return {"ingested": len(batch.events), "total_alerts": total_alerts}


@router.get("/events", summary="Query ingested events")
def query_events(
    source: str | None = None,
    event_type: str | None = None,
    with_alerts_only: bool = False,
    limit: int = Query(50, le=500),
) -> list[dict]:
    out = []
    for ev in reversed(_EVENT_LEDGER):
        if source and ev.source != source:
            continue
        if event_type and ev.payload.get("event_type") != event_type:
            continue
        if with_alerts_only and not ev.alerts:
            continue
        out.append(ev.to_dict())
        if len(out) >= limit:
            break
    return out


@router.get("/alerts", summary="Get raised alerts")
def get_alerts(severity: str | None = None, limit: int = Query(50, le=500)) -> list[dict]:
    alerts = []
    for ev in reversed(_EVENT_LEDGER):
        for a in ev.alerts:
            if severity and a["severity"] != severity.upper():
                continue
            alerts.append({"event_id": ev.id, "source": ev.source,
                           "timestamp": ev.timestamp, **a})
            if len(alerts) >= limit:
                return alerts
    return alerts


@router.get("/rules", summary="List the active correlation rules")
def get_rules() -> list[dict]:
    return [
        {"id": r["id"], "name": r["name"], "severity": r["severity"],
         "description": r["description"]}
        for r in RULES
    ]
