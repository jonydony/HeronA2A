"""Flat-file store for evidence timelines + the public registry.

One JSON file per verified agent holds its full evidence timeline (append-only),
so an agent can point a counterparty at its history: "here is my evidence over
the last N days." A single registry.json indexes every agent + its latest record.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

_DATA = Path(__file__).resolve().parent.parent / "data"
_AGENTS = _DATA / "agents"
_REGISTRY = _DATA / "registry.json"


def _slug(agent_url: str) -> str:
    # Stable, filesystem-safe id derived from the agent's endpoint URL.
    return hashlib.sha256(agent_url.encode("utf-8")).hexdigest()[:16]


def agent_id(agent_url: str) -> str:
    return _slug(agent_url)


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
