"""In-repo schema bootstrap (Fable H4).

We can't spin a real Postgres here, but we can lock down that the shipped schema
parses into the four expected idempotent CREATE TABLE statements, so a fresh deploy
bootstraps instead of 500-ing.
"""
from __future__ import annotations

from app import store_pg


def test_schema_parses_into_four_idempotent_tables():
    stmts = store_pg._SCHEMA_STMTS
    creates = [s.lower() for s in stmts if "create table" in s.lower()]
    assert len(creates) == 4
    joined = " ".join(stmts).lower()
    for t in ("agents", "evidence", "reviews", "used_tokens"):
        assert f"create table if not exists {t}" in joined, f"missing/​non-idempotent: {t}"


def test_schema_has_no_stray_comment_statements():
    # every statement must be real DDL, not a swallowed comment block
    for s in store_pg._SCHEMA_STMTS:
        assert not s.lstrip().startswith("--")
        assert "create" in s.lower()
