"""Central configuration for the 5 security REST APIs.

All settings are runtime-tunable via environment variables (prefixed with
SECAPI_) so operators can wire up real threat feeds (VirusTotal, AbuseIPDB,
OSV, etc.) without code changes.
"""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SECAPI_", extra="ignore")

    # --- General ---
    app_name: str = "SecAPI — 5 Cybersecurity REST Services"
    api_version: str = "v1"

    # --- API 1: Password & breach intelligence ---
    # Upstream k-anonymity breach source. Defaults to the public HIBP Pwned
    # Passwords range endpoint (no API key needed for range lookups).
    hibp_range_url: str = "https://api.pwnedpasswords.com/range/"

    # --- API 3: IOC / indicator enrichment ---
    # AbuseIPDB (IP reputation) API key. Leave empty to run in offline/static mode.
    abuseipdb_api_key: str = ""
    abuseipdb_check_url: str = "https://api.abuseipdb.com/api/v2/check"

    # --- API 4: log ingestion limits ---
    max_log_batch_size: int = 5000

    # --- RapidAPI marketplace compatibility ---
    # When posting to RapidAPI, consumers send x-rapidapi-key / x-rapidapi-host.
    # Set EXPECTED_RAPIDAPI_HOST to your marketplace host (e.g.
    # "secapi.p.rapidapi.com") to reject requests that don't come through it.
    expected_rapidapi_host: str = ""


settings = Settings()
