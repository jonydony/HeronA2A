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

from . import llm, probe, sign, store, tokens

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
    signature: str              # reviewer sig over {subject_agent_id, outcome, note}


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
            "GET /register": "all verified agents + latest score + freshness",
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
        "mode": os.environ.get("HERON_MODE", "auto"),
        "reverify_cadence_days": _REVERIFY_DAYS,
        "rate_limit_per_hour": _LIMIT,
    }


@app.get("/skill.md", response_class=PlainTextResponse)
def skill_md():
    return _SKILL_MD.read_text() if _SKILL_MD.exists() else "SKILL.md missing"


@app.post("/verify", dependencies=[Depends(_rate_limit)])
async def verify(req: VerifyRequest):
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
    if not store.mark_token_used(info):  # info == nonce on success
        raise HTTPException(409, "token already used — one review per interaction")
    body = {"subject_agent_id": req.subject_agent_id, "outcome": req.outcome, "note": req.note}
    if not sign.verify(body, req.signature, req.reviewer_public_key):
        raise HTTPException(403, "reviewer signature does not verify over the review body")
    store.append_review(req.subject_agent_id, {
        **body, "reviewer": req.reviewer_public_key,
        "signature": req.signature, "recorded_at": _now_iso(),
    })
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
