"""Tests for IOC / indicator enrichment service."""
import pytest

from apis.ioc_enrich.service import (
    compute_hashes,
    enrich_hash,
    enrich_ip,
    enrich_url,
    KNOWN_BAD_HASHES,
)


def test_compute_hashes_known_values():
    h = compute_hashes(b"abc")
    assert h["sha1"] == "a9993e364706816aba3e25717850c26c9cd0d89d"
    assert h["md5"] == "900150983cd24fb0d6963f7d28e17f72"
    assert len(h["sha256"]) == 64


def test_enrich_hash_bad():
    # Register a known-bad hash to test against
    known = "44d88612fea8a8f36de82e1278abb02f"
    assert known in KNOWN_BAD_HASHES
    result = enrich_hash(known)
    assert result.malicious is True
    assert result.ioc_type == "hash"


def test_enrich_hash_invalid():
    with pytest.raises(ValueError):
        enrich_hash("zzz-not-a-hash")


def test_enrich_ip_private():
    result = enrich_ip("192.168.1.1")
    assert result.ioc_type == "ip"
    assert result.detail["is_private"] is True


def test_enrich_ip_invalid():
    with pytest.raises(ValueError):
        enrich_ip("999.999.999.999")


def test_enrich_url_suspicious():
    result = enrich_url("http://bit.ly/xyz123")
    assert result.malicious is True
    assert "url-shortener" in result.tags


def test_enrich_url_normal():
    result = enrich_url("https://example.com/products")
    assert result.malicious is False
    assert result.detail["host"] == "example.com"
