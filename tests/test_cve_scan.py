"""Tests for CVE / dependency scanning service."""
from apis.cve_scan.service import (
    version_is_vulnerable,
    scan_requirements,
    scan_package_json,
    CVE_ALIASES,
)


def test_version_comparison():
    assert version_is_vulnerable("1.0.0", "1.2.3")
    assert version_is_vulnerable("2.3.2", "2.3.3")
    assert not version_is_vulnerable("2.3.3", "2.3.3")
    assert not version_is_vulnerable("3.0.0", "2.3.3")


def test_scan_requirements_finds_flask_cve():
    man = "# requirements.txt\nFlask==2.2.0\nrequests==2.30.0\n"
    findings = scan_requirements(man)
    assert len(findings) == 2
    cves = {f.cve_id for f in findings}
    assert "CVE-2023-30861" in cves  # flask
    assert "CVE-2023-32681" in cves  # requests


def test_scan_requirements_patched_version_not_flagged():
    man = "Flask==2.3.3\n"
    findings = scan_requirements(man)
    assert findings == []


def test_scan_package_json():
    man = '{"dependencies": {"flask": "^2.0.0"}, "devDependencies": {"flask-cors": "3.0.0"}}'
    findings = scan_package_json(man)
    cves = {f.cve_id for f in findings}
    assert "CVE-2023-30861" in cves


def test_cve_alias_lookup():
    assert "CVE-2023-30861" in CVE_ALIASES
