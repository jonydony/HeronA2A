"""Flat-file store backend — the zero-infra fallback (local dev / tests).

Used when DATABASE_URL is unset. One JSON file per agent holds its evidence
timeline; registry.json indexes agents; reviews/ holds peer reviews; a used-token
list backs single-use interaction tokens. Not safe under concurrent writes — the
Postgres backend (store_pg) is the deployed one.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

_DATA = Path(__file__).resolve().parent.parent / "data"
_AGENTS = _DATA / "agents"
_REGISTRY = _DATA / "registry.json"
_REVIEWS = _DATA / "reviews"
_USED = _DATA / "used_tokens.json"


def agent_id(agent_url: str) -> str:
    return hashlib.sha256(agent_url.encode("utf-8")).hexdigest()[:16]


def append_evidence(record: dict) -> None:
    _AGENTS.mkdir(parents=True, exist_ok=True)
    aid = record["agent_id"]
    path = _AGENTS / f"{aid}.json"
    timeline = json.loads(path.read_text()) if path.exists() else []
    timeline.append(record)
    path.write_text(json.dumps(timeline, indent=2))
    _reindex(record)


def get_timeline(aid: str) -> list[dict]:
    path = _AGENTS / f"{aid}.json"
    return json.loads(path.read_text()) if path.exists() else []


def _reindex(record: dict) -> None:
    registry = json.loads(_REGISTRY.read_text()) if _REGISTRY.exists() else {}
    aid = record["agent_id"]
    timeline = get_timeline(aid)
    registry[aid] = {
        "agent_id": aid,
        "agent_url": record["agent_url"],
        "name": record.get("declared_name") or record["agent_url"],
        "latest_score": record["summary"]["score"],
        "latest_confidence": record["summary"]["confidence"],
        "last_verified_at": record["verified_at"],
        "verification_count": len(timeline),
        "first_verified_at": timeline[0]["verified_at"] if timeline else record["verified_at"],
        "reviews": registry.get(aid, {}).get("reviews", {"worked": 0, "partial": 0, "failed": 0, "total": 0}),
    }
    _REGISTRY.write_text(json.dumps(registry, indent=2))


def get_registry() -> list[dict]:
    if not _REGISTRY.exists():
        return []
    registry = json.loads(_REGISTRY.read_text())
    return sorted(registry.values(), key=lambda r: r["last_verified_at"], reverse=True)


def get_entry(aid: str) -> dict | None:
    if not _REGISTRY.exists():
        return None
    return json.loads(_REGISTRY.read_text()).get(aid)


def mark_token_used(nonce: str) -> bool:
    _DATA.mkdir(parents=True, exist_ok=True)
    used = json.loads(_USED.read_text()) if _USED.exists() else []
    if nonce in used:
        return False
    used.append(nonce)
    _USED.write_text(json.dumps(used))
    return True


def append_review(aid: str, review: dict) -> None:
    _REVIEWS.mkdir(parents=True, exist_ok=True)
    path = _REVIEWS / f"{aid}.json"
    reviews = json.loads(path.read_text()) if path.exists() else []
    reviews.append(review)
    path.write_text(json.dumps(reviews, indent=2))
    _reindex_reviews(aid, reviews)


def get_reviews(aid: str) -> list[dict]:
    # Keep the raw signature on disk, but strip it from what we publish (H2): don't
    # hand scrapers reusable signed tuples. Reviewer public key stays. (Note: the
    # stored sig isn't independently re-verifiable — the signed nonce isn't persisted.)
    path = _REVIEWS / f"{aid}.json"
    reviews = json.loads(path.read_text()) if path.exists() else []
    return [{k: v for k, v in r.items() if k != "signature"} for r in reviews]


def _reindex_reviews(aid: str, reviews: list[dict]) -> None:
    if not _REGISTRY.exists():
        return
    registry = json.loads(_REGISTRY.read_text())
    entry = registry.get(aid)
    if not entry:
        return
    counts = {"worked": 0, "partial": 0, "failed": 0}
    for r in reviews:
        if r.get("outcome") in counts:
            counts[r["outcome"]] += 1
    entry["reviews"] = {**counts, "total": len(reviews)}
    registry[aid] = entry
    _REGISTRY.write_text(json.dumps(registry, indent=2))
