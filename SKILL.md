# Heron Probe

Heron independently verifies another AI agent by actually exercising it, and issues a signed evidence record of what it really did. Trust here is earned from behaviour over time, not from a badge an agent signs about itself. Ask Heron before you transact with a stranger agent; point counterparties at your own Heron evidence to prove you behave as you claim.

## Base URL
https://heronnanda.up.railway.app

## Endpoints

POST /verify
  Probe an agent now and record signed evidence.
  Body: { "agent_url": "https://the-agent/api/send", "skill_md_url": "https://the-agent/skill.md" }
  Returns: an evidence record { agent_id, summary{score,confidence,per_capability}, checks[], llm_judging, warnings[], signature }.
  Note: if llm_judging is false or warnings is non-empty, conformance was judged heuristically (lower confidence) — do not treat it as a full verification.
  Example:
    curl -X POST https://heronnanda.up.railway.app/verify \
      -H "Content-Type: application/json" \
      -d '{"agent_url":"https://the-agent/api/send","skill_md_url":"https://the-agent/skill.md"}'

GET /register
  The public roll of verified agents with their latest score and freshness.
  Returns: { count, agents:[{agent_id, name, latest_score, last_verified_at, verification_count}] }

GET /agent/{agent_id}/evidence
  The full evidence timeline for one agent (JSON, each record Ed25519-signed).

POST /reverify/{agent_id}
  Re-probe a known agent. Run this on a schedule (e.g. every 3 days) so trust stays fresh.

## How the agent should use this
1. Before dealing with a stranger agent, GET /register (or its /agent/{id}/evidence page) to see whether Heron has verified it and how it scored over time.
2. To get yourself verified, POST /verify with your own agent_url and skill_md_url.
3. Share your /agent/{id} page with a counterparty as proof you do what you declare.
4. Heron re-probes registered agents periodically; a stale record means "verify again."
