# Deploy — Railway + Supabase

Container is ready (`Dockerfile`, `Procfile`). Storage is managed Postgres (Supabase). No server to stand up.

## 1. Supabase (the store)

1. [supabase.com](https://supabase.com) → **New project** (free tier). Pick a strong DB password.
2. Project → **Settings → Database → Connection string → URI**. Copy it (looks like `postgresql://postgres:<password>@<host>:5432/postgres`). Use the **connection pooler** URI if offered (better for a small web service).
3. Hold onto this — it becomes `DATABASE_URL` in Railway.

## 2. Signing key (stable identity across redeploys)

Generate once and keep it secret:

```bash
python -c "from app import sign; print(sign.private_seed_b64())"
```

This becomes `HERON_SIGNING_KEY`. If you skip it, Heron generates a throwaway key per deploy and every record's signature identity changes — don't skip it in production.

## 3. Railway (the service)

1. [railway.app](https://railway.app) → **New Project → Deploy from GitHub repo** → pick `jonydony/HeronA2A`. It builds the `Dockerfile`.
2. Railway → your service → **Variables** → add (this is the "paste the URLs" step):

   | Variable | Value |
   |---|---|
   | `DATABASE_URL` | the Supabase URI from step 1 |
   | `HERON_SIGNING_KEY` | the seed from step 2 |
   | `ANTHROPIC_API_KEY` | your Anthropic key (enables smart conformance judging; omit to run the free deterministic tier) |
   | `HERON_MODE` | *(optional)* `deterministic` to force the free tier even with a key |

   Railway sets `PORT` automatically; the container already binds to it.
3. Deploy. Railway gives a public HTTPS URL like `https://herona2a-production.up.railway.app`.
4. Smoke-test: `curl https://<your-url>/health` → should return `{"status":"ok", ...}`.

## 4. Publish + register

1. Put the Railway URL into [`SKILL.md`](SKILL.md) → `Base URL`, commit, push (Railway redeploys).
2. Register Heron on NANDA so agents discover it:
   - **nandatown skills page** — `POST https://nandatown.projectnanda.org/api/skills` with name + the SKILL.md link + endpoints, or via the web form.
   - **List39** (agent facts registry) if used.
3. Flip the GitHub repo to **public** when ready to submit.

## Notes

- No `DATABASE_URL` → Heron falls back to the local file store (fine for dev/tests, not for a redeployable server).
- Free-tier caveats: Supabase free projects pause after inactivity (first request wakes them); Railway free usage is limited — fine for early / demo traffic.
