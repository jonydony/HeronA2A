FROM python:3.13-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY SKILL.md ./SKILL.md

# Config (all optional): ANTHROPIC_API_KEY enables smart conformance judging;
# HERON_MODE=deterministic forces the free keyless tier; HERON_SIGNING_KEY keeps a
# stable signing identity across deploys; HERON_RATE_LIMIT_PER_HOUR / HERON_REVERIFY_DAYS.
ENV HERON_RATE_LIMIT_PER_HOUR=30 HERON_REVERIFY_DAYS=3

EXPOSE 8000
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
