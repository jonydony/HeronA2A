"""Postgres store backend (Supabase) — the deployed store.

Selected when DATABASE_URL is set. Concurrency-safe (real transactions), survives
redeploys. Returns the same shapes as the file backend: timestamps as ISO strings,
scores as floats, so the rest of the app doesn't care which backend is active.
"""
from __future__ import annotations

import hashlib
import os

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

_DSN = os.environ.get("DATABASE_URL", "")


def _conn():
    return psycopg.connect(_DSN, row_factory=dict_row)


def _iso(v):
    return v.isoformat() if hasattr(v, "isoformat") else v


def agent_id(agent_url: str) -> str:
    return hashlib.sha256(agent_url.encode("utf-8")).hexdigest()[:16]


def append_evidence(record: dict) -> None:
    aid = record["agent_id"]
    s = record["summary"]
    name = record.get("declared_name") or record["agent_url"]
    with _conn() as conn, conn.cursor() as cur:
        # Upsert the registry row first (evidence FK depends on it), bumping the count.
        cur.execute(
            """
            insert into agents (agent_id, agent_url, name, latest_score, latest_confidence,
                                last_verified_at, first_verified_at, verification_count)
            values (%s,%s,%s,%s,%s,%s,%s,1)
            on conflict (agent_id) do update set
              agent_url = excluded.agent_url,
              name = excluded.name,
              latest_score = excluded.latest_score,
              latest_confidence = excluded.latest_confidence,
              last_verified_at = excluded.last_verified_at,
              verification_count = agents.verification_count + 1
            """,
            (aid, record["agent_url"], name, s["score"], s["confidence"],
             record["verified_at"], record["verified_at"]),
        )
        cur.execute(
            "insert into evidence (agent_id, verified_at, record) values (%s,%s,%s)",
            (aid, record["verified_at"], Jsonb(record)),
        )


def get_timeline(aid: str) -> list[dict]:
    with _conn() as conn, conn.cursor() as cur:
        cur.execute("select record from evidence where agent_id=%s order by verified_at, id", (aid,))
        return [r["record"] for r in cur.fetchall()]


def _entry(row: dict) -> dict:
    return {
        "agent_id": row["agent_id"],
        "agent_url": row["agent_url"],
        "name": row["name"],
        "latest_score": float(row["latest_score"]) if row["latest_score"] is not None else None,
        "latest_confidence": float(row["latest_confidence"]) if row["latest_confidence"] is not None else None,
        "last_verified_at": _iso(row["last_verified_at"]),
        "first_verified_at": _iso(row["first_verified_at"]),
        "verification_count": row["verification_count"],
        "reviews": row["reviews"],
    }


def get_registry() -> list[dict]:
    with _conn() as conn, conn.cursor() as cur:
        cur.execute("select * from agents order by last_verified_at desc")
        return [_entry(r) for r in cur.fetchall()]


def get_entry(aid: str) -> dict | None:
    with _conn() as conn, conn.cursor() as cur:
        cur.execute("select * from agents where agent_id=%s", (aid,))
        row = cur.fetchone()
        return _entry(row) if row else None


def mark_token_used(nonce: str) -> bool:
    with _conn() as conn, conn.cursor() as cur:
        cur.execute("insert into used_tokens (nonce) values (%s) on conflict (nonce) do nothing", (nonce,))
        return cur.rowcount == 1


def append_review(aid: str, review: dict) -> None:
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            "insert into reviews (agent_id, reviewer, outcome, note, signature, recorded_at) "
            "values (%s,%s,%s,%s,%s,%s)",
            (aid, review["reviewer"], review["outcome"], review.get("note", ""),
             review["signature"], review["recorded_at"]),
        )
        cur.execute(
            """
            update agents set reviews = (
              select jsonb_build_object(
                'worked',  count(*) filter (where outcome='worked'),
                'partial', count(*) filter (where outcome='partial'),
                'failed',  count(*) filter (where outcome='failed'),
                'total',   count(*))
              from reviews where agent_id=%s)
            where agent_id=%s
            """,
            (aid, aid),
        )


def get_reviews(aid: str) -> list[dict]:
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            "select reviewer, outcome, note, signature, recorded_at from reviews "
            "where agent_id=%s order by id", (aid,))
        return [{
            "subject_agent_id": aid, "outcome": r["outcome"], "note": r["note"],
            "reviewer": r["reviewer"], "signature": r["signature"],
            "recorded_at": _iso(r["recorded_at"]),
        } for r in cur.fetchall()]
