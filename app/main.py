"""Heron Probe — a NANDA trust service that earns agent trust from behaviour over time.

Agent-facing JSON API (no human dashboard). Consumers are other agents: they read
SKILL.md, POST /verify, and GET the JSON registry / evidence.

  GET  /health              liveness + Heron's signing public key
  GET  /skill.md            Heron's own SKILL.md (so another agent can call us unaided)
  POST /verify              {agent_url, skill_md_url?} -> run probes, append signed evidence
  POST /reverify/{id}       re-probe a known agent (the "every 3 days" continuous step)
  GET  /register            JSON list of all verified agents + freshness + score
  GET  /agent/{id}/evidence JSON evidence timeline for one agent (each record Ed25519-signed)
  GET  /                    JSON API index
"""
from __future__ import annotations

import datetime as _dt
import os
import time
from collections import defaultdict
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel

from . import llm, net, probe, sign, store, tokens

app = FastAPI(title="Heron Probe", version="0.1")
_SKILL_MD = Path(__file__).resolve().parent.parent / "SKILL.md"

# --- guardrails: a fixed-window per-IP rate limit so /verify can't be flooded to
# burn our LLM budget. The abusable surface is small anyway (deterministic tier is
# free), but this caps the flood vector. Tune via env.
_LIMIT = int(os.environ.get("HERON_RATE_LIMIT_PER_HOUR", "30"))
_WINDOW = 3600
_REVERIFY_DAYS = float(os.environ.get("HERON_REVERIFY_DAYS", "3"))
_hits: dict[str, list[float]] = defaultdict(list)


def _rate_limit(request: Request):
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    _hits[ip] = [t for t in _hits[ip] if now - t < _WINDOW]
    if len(_hits[ip]) >= _LIMIT:
        raise HTTPException(429, f"rate limit: {_LIMIT} verifications/hour")
    _hits[ip].append(now)


def _stale(last_verified_iso: str) -> bool:
    last = _dt.datetime.fromisoformat(last_verified_iso)
    age_days = (_dt.datetime.now(_dt.timezone.utc) - last).total_seconds() / 86400
    return age_days >= _REVERIFY_DAYS


class VerifyRequest(BaseModel):
    agent_url: str
    skill_md_url: str | None = None


class ReviewRequest(BaseModel):
    subject_agent_id: str
    token: dict                 # the interaction token from /verify
    reviewer_public_key: str    # base64 ed25519 — the reviewer's stable identity
    outcome: str                # worked | partial | failed
    note: str = ""
    signature: str              # reviewer sig over {subject_agent_id, outcome, note, nonce}


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


@app.get("/")
def index():
    return {
        "service": "Heron Probe",
        "what": "independent, continuous, behaviour-earned trust for AI agents",
        "endpoints": {
            "POST /verify": "{agent_url, skill_md_url?} -> signed evidence record + interaction token",
            "POST /review": "token-bound, signed peer review of an agent you probed through us",
            "POST /reverify/{id}": "re-probe a known agent (explicit, on request)",
            "POST /reverify-all": "RESERVED / disabled (no unprompted mass re-probing)",
            "GET /register": "all verified agents + trust score (best of recent runs) + latest run + freshness",
            "GET /agent/{id}/evidence": "full signed evidence timeline for one agent",
            "GET /skill.md": "how an agent calls Heron",
            "GET /health": "liveness + signing public key",
        },
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": probe.VERIFIER,
        "public_key": sign.public_key_b64(),
        "backend": store.backend,
        "llm_judging": llm.available(),
        "llm_calls_used": llm.calls_used(),
        "mode": os.environ.get("HERON_MODE", "auto"),
        "reverify_cadence_days": _REVERIFY_DAYS,
        "rate_limit_per_hour": _LIMIT,
    }


@app.get("/skill.md", response_class=PlainTextResponse)
def skill_md():
    return _SKILL_MD.read_text() if _SKILL_MD.exists() else "SKILL.md missing"


@app.post("/verify", dependencies=[Depends(_rate_limit)])
async def verify(req: VerifyRequest):
    # SSRF gate up front: reject internal/metadata targets with a clear 400 instead of
    # producing a record whose probe bodies reflect an internal service's response.
    for label, url in (("agent_url", req.agent_url), ("skill_md_url", req.skill_md_url)):
        if url:
            try:
                net.assert_public_url(url)
            except net.UnsafeURLError as exc:
                raise HTTPException(400, f"{label} rejected: {exc}")
    # M10: the skill card must live on the agent's own origin, so a caller can't tank a
    # competitor's score by pointing us at a mismatched / malicious SKILL.md.
    if req.skill_md_url and not net.same_origin(req.agent_url, req.skill_md_url):
        raise HTTPException(400, "skill_md_url must be same-origin as agent_url")
    record = await probe.run_verification(req.agent_url, req.skill_md_url)
    # Hand the caller a single-use interaction token so it can leave one review later.
    token = tokens.issue(record["agent_id"])
    return JSONResponse({**record, "interaction_token": token})


@app.post("/review", dependencies=[Depends(_rate_limit)])
def review(req: ReviewRequest):
    if req.outcome not in ("worked", "partial", "failed"):
        raise HTTPException(422, "outcome must be one of: worked, partial, failed")
    if len(req.note) > 280:
        raise HTTPException(422, "note too long (max 280 chars)")
    if not store.get_entry(req.subject_agent_id):
        raise HTTPException(404, "unknown agent — probe it first via /verify")
    ok, info = tokens.verify(req.token, req.subject_agent_id)
    if not ok:
        raise HTTPException(403, f"invalid interaction token: {info}")
    nonce = info  # info == nonce on success
    # H2: bind the reviewer signature to this token's nonce, so a scraped signed
    # review can't be replayed against a different (fresh) token.
    body = {"subject_agent_id": req.subject_agent_id, "outcome": req.outcome,
            "note": req.note, "nonce": nonce}
    # M6: verify the reviewer signature BEFORE touching the token, so a bad signature
    # can't spend a legitimate single-use token.
    if not sign.verify(body, req.signature, req.reviewer_public_key):
        raise HTTPException(403, "reviewer signature does not verify over the review body")
    # Fable: burn the nonce and record the review atomically, so a failed write can't
    # burn the caller's token with no review recorded.
    recorded = store.append_review_and_burn(req.subject_agent_id, nonce, {
        "subject_agent_id": req.subject_agent_id, "outcome": req.outcome, "note": req.note,
        "reviewer": req.reviewer_public_key, "signature": req.signature, "nonce": nonce,
        "recorded_at": _now_iso(),
    })
    if not recorded:
        raise HTTPException(409, "token already used — one review per interaction")
    return {"status": "recorded", "subject_agent_id": req.subject_agent_id,
            "reviews": (store.get_entry(req.subject_agent_id) or {}).get("reviews")}


@app.post("/reverify/{aid}", dependencies=[Depends(_rate_limit)])
async def reverify(aid: str):
    timeline = store.get_timeline(aid)
    if not timeline:
        raise HTTPException(404, "unknown agent id")
    last = timeline[-1]
    record = await probe.run_verification(last["agent_url"], last.get("skill_md_url"))
    return JSONResponse(record)


@app.post("/reverify-all")
async def reverify_all():
    """RESERVED / DISABLED. Automatic continuous re-probing is intentionally off:
    Heron does not go out and hit other agents unprompted. Re-verification happens
    only when someone explicitly asks (POST /verify or /reverify/{id})."""
    raise HTTPException(503, "auto re-verify is disabled; re-verify explicitly via /verify or /reverify/{id}")


@app.get("/register")
def register():
    agents = store.get_registry()
    return {"count": len(agents), "agents": agents}


@app.get("/agent/{aid}/evidence")
def evidence(aid: str):
    timeline = store.get_timeline(aid)
    if not timeline:
        raise HTTPException(404, "unknown agent id")
    return {"agent_id": aid, "count": len(timeline), "timeline": timeline,
            "reviews": store.get_reviews(aid)}
