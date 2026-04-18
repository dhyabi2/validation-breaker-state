FROM ghcr.io/nesquena/hermes-webui:latest

# Run as root from the start: DO App Platform sets no_new_privileges which
# blocks the upstream init script's sudo-based UID switching. Running as root
# is allowed and sidesteps the whole dance.
USER root

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*

# Hermes Agent at /hermes (for iterate.py's subprocess retry path)
RUN git clone --depth 1 https://github.com/NousResearch/hermes-agent.git /hermes
RUN pip install --no-cache-dir --break-system-packages -e /hermes 'psycopg[binary]' pyyaml

# Bootstrap.py looks for hermes-agent at $HERMES_HOME/hermes-agent — symlink it
RUN mkdir -p /root/.hermes && ln -sf /hermes /root/.hermes/hermes-agent

# Seed skills: validation-breaker + hermes-feedback + iter script
RUN mkdir -p /seed-skills/security/validation-breaker /seed-skills/portal/hermes-feedback
COPY skills/validation-breaker/SKILL.md /seed-skills/security/validation-breaker/SKILL.md
COPY skills/hermes-feedback/SKILL.md    /seed-skills/portal/hermes-feedback/SKILL.md
COPY scripts/iterate.py /iterate.py
COPY scripts/do-entrypoint.sh /do-entrypoint.sh
RUN chmod +x /do-entrypoint.sh

ENV HERMES_WEBUI_HOST=0.0.0.0 \
    HERMES_WEBUI_PORT=8787 \
    HERMES_HOME=/root/.hermes \
    HERMES_WEBUI_AGENT_DIR=/hermes \
    HERMES_WEBUI_SKIP_ONBOARDING=1

EXPOSE 8787

CMD ["/do-entrypoint.sh"]
