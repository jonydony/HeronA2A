"""Interaction tokens — the anti-fake-review anchor.

When Heron probes agent X for a caller, it hands the caller a signed interaction
token for X. A review is only accepted with a valid token, so you cannot review
an agent you never engaged through Heron. Each token is single-use (its nonce is
burned on first review), so one interaction yields one review — no review-bombing.
Honest limit: the token proves "you probed X through us", not "you then used X".
"""
from __future__ import annotations

import datetime as _dt
import secrets

from . import sign


def issue(subject_agent_id: str) -> dict:
    payload = {
        "subject_agent_id": subject_agent_id,
        "nonce": secrets.token_hex(12),
        "issued_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
    }
    return {"payload": payload, "signature": sign.sign(payload)}


def verify(token: dict, subject_agent_id: str) -> tuple[bool, str]:
    """Verify the token is a real Heron-issued token for this subject. (Nonce
    single-use is enforced separately by the store, since that needs persistence.)"""
    try:
        p, s = token["payload"], token["signature"]
        if p.get("subject_agent_id") != subject_agent_id:
            return False, "token subject does not match the reviewed agent"
        if not sign.verify(p, s["value"], s["public_key"]):
            return False, "token signature invalid"
        if s["public_key"] != sign.public_key_b64():
            return False, "token not issued by this Heron instance"
        return True, p["nonce"]
    except Exception as exc:
        return False, f"malformed token ({exc})"
