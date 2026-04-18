FROM ghcr.io/nesquena/hermes-webui:latest

USER root

# Install system deps needed for iter loop (git for hermes-agent, build tools for psycopg)
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*

# Install hermes-agent at /hermes (so iterate.py's subprocess /hermes/cli.py retry path works)
RUN git clone --depth 1 https://github.com/NousResearch/hermes-agent.git /hermes
RUN pip install --no-cache-dir --break-system-packages -e /hermes 'psycopg[binary]'

# Seed skill file + iter script
RUN mkdir -p /seed-skills/security/validation-breaker
COPY skills/validation-breaker/SKILL.md /seed-skills/security/validation-breaker/SKILL.md
COPY scripts/iterate.py /iterate.py
COPY scripts/do-entrypoint.sh /do-entrypoint.sh
RUN chmod +x /do-entrypoint.sh

# Ensure the webui user can read the iter script + seed skills
RUN chmod -R 755 /seed-skills /iterate.py /do-entrypoint.sh

# Expose the webui port (DO App Platform Service consumes this)
EXPOSE 8787

# Switch back to the upstream user and run our wrapper, which launches
# iter as a background task and exec's the upstream init script.
USER hermeswebuitoo
CMD ["/do-entrypoint.sh"]
