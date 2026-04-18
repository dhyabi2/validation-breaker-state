#!/bin/bash
# DO App Platform entrypoint (runs as root, bypasses the image's sudo dance)
set +e

# Seed skills on first boot (idempotent: -n skips if exists)
mkdir -p /root/.hermes/skills/security/validation-breaker 2>/dev/null
cp -n /seed-skills/security/validation-breaker/SKILL.md \
      /root/.hermes/skills/security/validation-breaker/SKILL.md 2>/dev/null

# iter loop: hourly, background
(
  sleep 25  # let webui bind first
  while true; do
    echo "[$(date -u +%FT%TZ)] iter start" >&2
    python3 /iterate.py 2>&1 || echo "[$(date -u +%FT%TZ)] iter failed exit=$?" >&2
    echo "[$(date -u +%FT%TZ)] iter sleep 3600" >&2
    sleep 3600
  done
) &

# Hermes WebUI on :8787
cd /apptoo
exec python3 bootstrap.py --no-browser
