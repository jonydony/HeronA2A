"""Interaction tokens — the anti-fake-review anchor.

When Heron probes agent X for a caller, it hands the caller a signed interaction
token for X. A review is only accepted with a valid token, so you cannot review
an agent you never engaged through Heron. Each token is single-use (its nonce is
burned on first review), so one interaction yields one review — no review-bombing.
The token also carries an expiry, so a leaked token can't be banked indefinitely.

The token's nonce is the binding value: the reviewer signs it INTO the review body
(see main.review), so a scraped signed review can't be replayed against a fresh
token. Honest limit: the token proves "you probed X through us", not "you used X".
"""
from __future__ import annotations

import datetime as _dt
import os
import secrets

from . import sign

_TTL_HOURS = float(os.environ.get("HERON_TOKEN_TTL_HOURS", "24"))


def issue(subject_agent_id: str) -> dict:
    now = _dt.datetime.now(_dt.timezone.utc)
    payload = {
        "subject_agent_id": subject_agent_id,
        "nonce": secrets.token_hex(12),
        "issued_at": now.isoformat(),
        "expires_at": (now + _dt.timedelta(hours=_TTL_HOURS)).isoformat(),
    }
    return {"payload": payload, "signature": sign.sign(payload)}


def verify(token: dict, subject_agent_id: str) -> tuple[bool, str]:
    """Verify the token is a real, unexpired Heron-issued token for this subject.
    On success returns (True, nonce) — the nonce both burns single-use (via the
    store) and binds the reviewer signature (via main.review)."""
    try:
        p, s = token["payload"], token["signature"]
        if p.get("subject_agent_id") != subject_agent_id:
            return False, "token subject does not match the reviewed agent"
        if not sign.verify(p, s["value"], s["public_key"]):
            return False, "token signature invalid"
        if s["public_key"] != sign.public_key_b64():
            return False, "token not issued by this Heron instance"
        expires_at = p.get("expires_at")
        if expires_at:
            if _dt.datetime.now(_dt.timezone.utc) >= _dt.datetime.fromisoformat(expires_at):
                return False, "token expired"
        return True, p["nonce"]
    except Exception as exc:
        return False, f"malformed token ({exc})"
