#!/bin/bash
# DO App Platform entrypoint (runs as root).
# Bypasses both (a) the upstream init script's sudo dance (blocked by no_new_privileges)
# and (b) bootstrap.py which daemonizes + exits (causes DeployContainerExitZero).
# Runs server.py directly in the foreground.
set +e

# Seed skill
mkdir -p /root/.hermes/skills/security/validation-breaker 2>/dev/null
cp -n /seed-skills/security/validation-breaker/SKILL.md \
      /root/.hermes/skills/security/validation-breaker/SKILL.md 2>/dev/null
mkdir -p /root/.hermes/webui 2>/dev/null

# iter loop: hourly, background
(
  sleep 25
  while true; do
    echo "[$(date -u +%FT%TZ)] iter start" >&2
    python3 /iterate.py 2>&1 || echo "[$(date -u +%FT%TZ)] iter failed exit=$?" >&2
    echo "[$(date -u +%FT%TZ)] iter sleep 3600" >&2
    sleep 3600
  done
) &

# Hermes WebUI server in foreground — server.py runs the ASGI loop
export HERMES_WEBUI_HOST="${HERMES_WEBUI_HOST:-0.0.0.0}"
export HERMES_WEBUI_PORT="${HERMES_WEBUI_PORT:-8787}"
export HERMES_WEBUI_STATE_DIR="${HERMES_WEBUI_STATE_DIR:-/root/.hermes/webui}"
export HERMES_WEBUI_AGENT_DIR="${HERMES_WEBUI_AGENT_DIR:-/hermes}"

cd /hermes
exec python3 /apptoo/server.py
