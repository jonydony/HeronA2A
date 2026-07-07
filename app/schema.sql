-- Heron A2A registry schema (Fable H4).
-- Idempotent: store_pg runs this once on first connect so a FRESH Postgres/Supabase
-- database bootstraps itself instead of 500-ing on the first query. On the already
-- provisioned production DB every statement is a no-op (IF NOT EXISTS).
-- Column types mirror the live Supabase tables exactly (verified 2026-07-07).

create table if not exists agents (
    agent_id           text primary key,
    agent_url          text not null,
    name               text,
    skill_md_url       text,
    latest_score       numeric,
    latest_confidence  numeric,
    last_verified_at   timestamptz,
    first_verified_at  timestamptz,
    verification_count integer not null default 0,
    reviews            jsonb not null default '{"total":0,"failed":0,"worked":0,"partial":0}'::jsonb
);

create table if not exists evidence (
    id          bigint generated always as identity primary key,
    agent_id    text not null references agents(agent_id),
    verified_at timestamptz not null,
    record      jsonb not null
);

create table if not exists reviews (
    id          bigint generated always as identity primary key,
    agent_id    text not null references agents(agent_id),
    reviewer    text not null,
    outcome     text not null,
    note        text not null default '',
    signature   text not null,
    nonce       text,
    recorded_at timestamptz not null
);

-- Back-compat for DBs created before the signed nonce was stored (idempotent): the
-- reviewer signature is over {subject, outcome, note, nonce}, so persisting the nonce
-- makes a stored review independently re-verifiable in an audit.
alter table reviews add column if not exists nonce text;

create table if not exists used_tokens (
    nonce   text primary key,
    used_at timestamptz not null default now()
);

create index if not exists evidence_agent_idx on evidence (agent_id, verified_at, id);
create index if not exists reviews_agent_idx on reviews (agent_id, id);
