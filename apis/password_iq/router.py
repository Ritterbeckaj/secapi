"""REST endpoints for Password & breach intelligence."""
from __future__ import annotations

import aiohttp

from fastapi import APIRouter, HTTPException, Path, Query
from pydantic import BaseModel, Field

from config import settings
from .service import sha1_prefix, password_strength, parse_range_response

router = APIRouter()


class PasswordIn(BaseModel):
    password: str = Field(..., min_length=1, description="Password to check")


class HashIn(BaseModel):
    sha1_hex: str = Field(..., min_length=40, max_length=40, description="Full SHA-1 (hex)")


@router.get("/strength", summary="Score a password's strength (local only, never transmitted)")
def strength(
    password: str = Query(..., min_length=1, description="Password to score"),
) -> dict:
    result = password_strength(password)
    return {
        "score": result.score,
        "label": result.label,
        "entropy_bits": result.entropy_bits,
        "checks": result.checks,
        "suggestions": result.suggestions,
    }


@router.post("/breach", summary="k-anonymity breach lookup (HIBP range)")
async def breach(body: PasswordIn) -> dict:
    """Check if a password has appeared in a known breach.

    The password travels in the request body (never in URLs/logs). Implements
    k-anonymity: only the first 5 chars of the SHA-1 hash leave the machine.
    """
    password = body.password
    prefix, suffix = sha1_prefix(password)
    url = f"{settings.hibp_range_url}{prefix}"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    raise HTTPException(
                        502, f"Upstream breach source returned HTTP {resp.status}"
                    )
                body = await resp.text()
    except aiohttp.ClientError as exc:
        raise HTTPException(502, f"Failed to contact breach source: {exc}") from exc

    counts = parse_range_response(body)
    times = counts.get(suffix, 0)

    return {
        "password_provided": True,
        "hash_prefix": prefix,
        "confirmed_breached": times > 0,
        "times_seen": times,
        "k_anonymity": f"Only {prefix} was transmitted (suffix matched locally)",
    }


@router.get("/hash/{sha1_hex}", summary="Look up an arbitrary SHA-1 hash's breach count")
async def hash_lookup(
    sha1_hex: str = Path(..., min_length=40, max_length=40, description="Full SHA-1 (hex)"),
) -> dict:
    """Check breach count for a full SHA-1 hash value directly."""
    sha1_hex = sha1_hex.upper()
    if not all(c in "0123456789ABCDEF" for c in sha1_hex):
        raise HTTPException(422, "SHA-1 must be hexadecimal")
    prefix, suffix = sha1_hex[:5], sha1_hex[5:]

    url = f"{settings.hibp_range_url}{prefix}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    raise HTTPException(502, f"Upstream returned HTTP {resp.status}")
                body = await resp.text()
    except aiohttp.ClientError as exc:
        raise HTTPException(502, f"Failed to contact breach source: {exc}") from exc

    counts = parse_range_response(body)
    return {"hash_prefix": prefix, "times_seen": counts.get(suffix, 0)}
