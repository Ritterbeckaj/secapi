"""Tests for Password & breach intelligence service."""
import pytest

from apis.password_iq.service import (
    sha1_prefix,
    parse_range_response,
    password_strength,
)


def test_sha1_prefix_split():
    prefix, suffix = sha1_prefix("password123")
    # SHA-1 of password123 = CBFDAC6008F9CAB4083784CBD1874F76618D2A97
    assert prefix == "CBFDA"
    assert suffix == "C6008F9CAB4083784CBD1874F76618D2A97"


def test_parse_range_response():
    body = "ABCDEF:3\nC6008F9CAB4083784CBD1874F76618D2A97:99\nBADONLY\n"
    counts = parse_range_response(body)
    assert counts["ABCDEF"] == 3
    assert counts["C6008F9CAB4083784CBD1874F76618D2A97"] == 99
    assert counts["BADONLY"] == 0


def test_strength_empty():
    s = password_strength("")
    assert s.score == 0
    assert s.label == "very_weak"


def test_strength_strong():
    s = password_strength("Xk9#mQ2!vLp7$zR4")
    assert s.score >= 80
    assert s.label == "strong"


def test_strength_common_word_penalty():
    s = password_strength("password123")
    assert s.score < 80


def test_strength_bounds():
    for pw in ["a", "abcdef", "Password1!", "SuperDuperLongPassword99#!!"]:
        s = password_strength(pw)
        assert 0 <= s.score <= 100
