FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*

# Install Hermes from Nous Research
RUN git clone --depth 1 https://github.com/NousResearch/hermes-agent.git /hermes
WORKDIR /hermes
RUN pip install --no-cache-dir -e . && pip install --no-cache-dir 'psycopg[binary]'

# Seed Hermes skills directory
RUN mkdir -p /root/.hermes/skills/security/validation-breaker
COPY skills/validation-breaker/SKILL.md /root/.hermes/skills/security/validation-breaker/SKILL.md
COPY scripts/iterate.py /iterate.py

# Entrypoint: hourly loop (stays alive as a DO App Platform Worker)
CMD ["bash", "-c", "while true; do echo \"[$(date -u +%FT%TZ)] iter start\"; python /iterate.py || echo \"[$(date -u +%FT%TZ)] iter failed $?\"; echo \"[$(date -u +%FT%TZ)] sleeping 3600s\"; sleep 3600; done"]
