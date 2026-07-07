"""Store dispatcher.

Picks the backend by environment: DATABASE_URL set -> Postgres (store_pg, the
deployed store); unset -> flat files (store_files, zero-infra for local/tests).
Both expose the same interface, so the rest of the app calls store.* and never
cares which is active.
"""
from __future__ import annotations

import os

if os.environ.get("DATABASE_URL"):
    from . import store_pg as _b
else:
    from . import store_files as _b

agent_id = _b.agent_id
append_evidence = _b.append_evidence
get_timeline = _b.get_timeline
get_registry = _b.get_registry
get_entry = _b.get_entry
mark_token_used = _b.mark_token_used
append_review = _b.append_review
append_review_and_burn = _b.append_review_and_burn
get_reviews = _b.get_reviews

backend = "postgres" if os.environ.get("DATABASE_URL") else "files"
