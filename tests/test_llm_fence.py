"""Randomized untrusted-content fence (Fable M8)."""
from __future__ import annotations

from app import llm


def test_fence_uses_random_per_call_delimiter():
    note1, wrapped1 = llm._fence("hello")
    note2, wrapped2 = llm._fence("hello")
    # different random tag each call -> a target can't hardcode the closing marker
    assert wrapped1 != wrapped2
    # the note and the wrapped block share the SAME tag within one call
    tag1 = wrapped1.split(">>>", 1)[0].rsplit("-", 1)[1]
    assert f"<<<END-{tag1}>>>" in wrapped1
    assert tag1 in note1
    # the old fixed marker is gone
    assert "<<<END_UNTRUSTED>>>" not in wrapped1


def test_fence_wraps_the_payload():
    _, wrapped = llm._fence("PAYLOAD-XYZ")
    assert "PAYLOAD-XYZ" in wrapped
