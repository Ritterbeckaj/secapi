"""Password & breach intelligence service.

Solves the common problem: "was this password/account exposed in a breach —
without uploading the plaintext password to anyone?"

Implements the k-anonymity model pioneered by HIBP's Pwned Passwords:
the client only ever sends the first 5 hex chars of the SHA-1 hash, and the
server returns only the matching suffix list. Neither party learns the full
hash, so a plaintext password is never transmitted.
"""
from __future__ import annotations

import hashlib
import re
import string
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Core operations (pure, unit-testable)
# ---------------------------------------------------------------------------


def sha1_prefix(password: str) -> tuple[str, str]:
    """Return (prefix, suffix) of the SHA-1 of a password (k-anonymity split)."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return digest[:5], digest[5:]


def parse_range_response(body: str) -> dict[str, int]:
    """Parse HIBP range response ('SUFFIX:COUNT\\n...') into {suffix: count}."""
    counts: dict[str, int] = {}
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        suffix, _, count = line.partition(":")
        counts[suffix.upper()] = int(count or 0)
    return counts


@dataclass(frozen=True)
class Strength:
    score: int          # 0..100
    label: str          # very_weak .. strong
    entropy_bits: float
    checks: list[str]   # human-readable findings
    suggestions: list[str]


def password_strength(password: str) -> Strength:
    """Score a password without storing/transmitting it."""
    checks: list[str] = []
    suggestions: list[str] = []
    score = 0

    if not password:
        return Strength(0, "very_weak", 0.0, ["Empty password"], ["Use a non-empty password"])

    length = len(password)
    if length >= 16:
        score += 25
        checks.append("Good length (>= 16 characters)")
    elif length >= 12:
        score += 20
        checks.append("Acceptable length (>= 12 characters)")
    elif length >= 8:
        score += 12
        checks.append("Minimum length met (>= 8 characters)")
    else:
        suggestions.append("Use at least 12–16 characters")

    pools = 0
    if re.search(r"[a-z]", password):
        pools += 1
    if re.search(r"[A-Z]", password):
        pools += 1
    if re.search(r"\d", password):
        pools += 1
    if re.search(r"[^A-Za-z0-9]", password):
        pools += 1

    unique = len(set(password))
    pool_size = 0
    if re.search(r"[a-z]", password):
        pool_size += 26
    if re.search(r"[A-Z]", password):
        pool_size += 26
    if re.search(r"\d", password):
        pool_size += 10
    if re.search(r"[^A-Za-z0-9]", password):
        pool_size += 32

    entropy_bits = length * (pool_size.bit_length() - 1) if pool_size else 0.0

    score += pools * 12  # up to 48
    if unique >= length * 0.8:
        score += 7
        checks.append("High character variety")
    else:
        suggestions.append("Avoid repeating characters")

    # Naive common-pattern penalties
    common = ["123456", "password", "qwerty", "letmein", "admin", "welcome", "111111", "abc123"]
    low = password.lower()
    if any(p in low for p in common):
        score -= 20
        checks.append("Contains a common/guessable substring")
        suggestions.append("Avoid common words and number sequences")
    if low in {"password", "password123", "12345678"}:
        score = 0

    score = max(0, min(100, score))

    if score >= 80:
        label = "strong"
    elif score >= 55:
        label = "ok"
    elif score >= 30:
        label = "weak"
    else:
        label = "very_weak"

    return Strength(score, label, round(entropy_bits, 1), checks, suggestions)
