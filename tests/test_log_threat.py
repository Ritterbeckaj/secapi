"""Tests for Threat log correlation & alerting service."""
from apis.log_threat.service import ingest_event, RULES


def test_rules_present():
    ids = {r["id"] for r in RULES}
    assert "R-1001" in ids


def test_failed_login_rule_after_threshold():
    for i in range(6):
        ev = ingest_event(
            "auth.log",
            {"event_type": "authentication", "success": False,
             "source_ip": "203.0.113.99", "attempt": i},
        )
    # The 6th event should trip the >5 threshold rule
    assert ev.alerts, "expected an alert after 6 rapid failures"
    assert ev.alerts[0]["rule_id"] == "R-1001"


def test_single_failed_login_no_alert():
    ev = ingest_event("auth.log",
                      {"event_type": "authentication", "success": False,
                       "source_ip": "198.51.100.5"})
    assert ev.alerts == []


def test_privilege_escalation_alert():
    ev = ingest_event("ossec", {"event_type": "privilege", "action": "grant",
                                "user": "bob"})
    assert ev.alerts and ev.alerts[0]["rule_id"] == "R-1003"


def test_exfiltration_alert():
    ev = ingest_event("fw", {"event_type": "network", "direction": "outbound",
                             "bytes": 150_000_000})
    assert ev.alerts and ev.alerts[0]["rule_id"] == "R-1004"
