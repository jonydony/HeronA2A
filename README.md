# Heron Probe

Independent, continuous, behaviour-earned trust for AI agents — built for the MIT NANDA ecosystem.

Over the NANDA wire a stranger agent exposes only two things: what it **declares** about itself (its `SKILL.md`) and how it **responds** on its HTTP endpoint. No traces, no receipts, no way to look inside. Existing trust services (e.g. Town Notary) verify a badge the agent signs about *itself* — passive self-attestation.

Heron does the thing nobody else does: it **actively exercises** a stranger agent and records what it really did.

- **Conformance** — does the agent actually do what its `SKILL.md` claims? (LLM-judged, cross-probe.)
- **Safety** — does it hold under adversarial input: secret-leak, prompt-injection, out-of-scope destructive requests? (Deterministic — canary tokens / secret regex, unfakeable.)

Each run produces an **Ed25519-signed evidence record** appended to that agent's timeline. Re-probing on a schedule (`/reverify-all`, default every 3 days) turns a one-time check into a **living trust record**: an agent points a counterparty at its evidence and says "here is independent proof, refreshed, that I behave as I claim."

> Trust is behaviour over time, not a stamp.

Agent-facing **JSON API only** — consumers are other agents (no human dashboard).

## Endpoints

| | |
|---|---|
| `POST /verify` | `{agent_url, skill_md_url?}` → run probes, append a signed evidence record |
| `POST /reverify/{id}` | re-probe one known agent |
| `POST /reverify-all?force=` | re-probe every agent past the cadence (the continuous step) |
| `GET /register` | all verified agents + latest score + freshness |
| `GET /agent/{id}/evidence` | full signed evidence timeline for one agent |
| `GET /skill.md` | how an agent calls Heron |
| `GET /health` | liveness, signing public key, mode |

## Quickstart

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

# demo target (good behaviour; HERON_MOCK_MODE=bad for a misbehaving one)
uvicorn app.mocktarget:app --port 9100 &
uvicorn app.main:app --port 8000 &

curl -X POST http://127.0.0.1:8000/verify -H 'content-type: application/json' \
  -d '{"agent_url":"http://127.0.0.1:9100/api/send","skill_md_url":"http://127.0.0.1:9100/skill.md"}'
curl http://127.0.0.1:8000/register
```

## Configuration (all env, all optional)

| Var | Default | Effect |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | enables LLM probe-planning + cross-probe conformance judging. Without it, Heron runs the free deterministic tier (safety + heuristic conformance). |
| `HERON_MODE` | `auto` | `deterministic` forces the keyless tier even if a key is set (the free, un-abusable tier). |
| `HERON_PLAN_MODEL` | `claude-sonnet-5` | model for probe planning (quality lever). |
| `HERON_JUDGE_MODEL` | `claude-haiku-4-5-20251001` | model for judging (cheap; Haiku ≈ Sonnet on verdicts, validated). |
| `HERON_SIGNING_KEY` | — | base64 of the 32-byte ed25519 seed — set it so a deployed instance keeps a **stable signing identity** across restarts. Print one with `python -c "from app import sign; print(sign.private_seed_b64())"`. |
| `HERON_RATE_LIMIT_PER_HOUR` | `30` | per-IP cap on `/verify` (flood guard). |
| `HERON_REVERIFY_DAYS` | `3` | cadence for `/reverify-all`. |

## Design notes

- **Safety is deterministic on purpose.** Canary-token echo and secret regex are unfakeable and reproducible — a stronger trust signal than "an LLM graded it."
- **Cross-probe judging is the quality lever.** The judge sees all of an agent's responses together, so it catches "same output for every input" that per-probe checks miss.
- **Opt-in / read-only by default.** Heron probes willing agents within their rate limits; write/stateful probes require the agent's authorization.

## Tests

```bash
pip install pytest && python -m pytest tests/ -q
```

## Deploy (next step)

Container is ready (`Dockerfile`, `Procfile`). To ship:
1. Deploy to any host (Railway / Render / Fly). Set `HERON_SIGNING_KEY` (stable identity) and, for smart judging, `ANTHROPIC_API_KEY`.
2. Put the real host into `SKILL.md` (`Base URL`).
3. Register on NANDA (List39 / the nandatown skills page) so agents can discover Heron.
