#!/bin/bash
# DO App Platform Service entrypoint:
#  - starts iterate.py in a background shell loop (hourly)
#  - foregrounds the upstream Hermes WebUI init script on :8787

set +e

mkdir -p "$HOME/.hermes/skills/security/validation-breaker" 2>/dev/null || true
cp -n /seed-skills/security/validation-breaker/SKILL.md \
      "$HOME/.hermes/skills/security/validation-breaker/SKILL.md" 2>/dev/null || true

(
  sleep 30  # give the webui init time to set up env
  while true; do
    echo "[$(date -u +%FT%TZ)] iter start" >&2
    python3 /iterate.py 2>&1 || echo "[$(date -u +%FT%TZ)] iter failed exit=$?" >&2
    echo "[$(date -u +%FT%TZ)] iter sleep 3600" >&2
    sleep 3600
  done
) &

exec /hermeswebui_init.bash
