---
name: validation-breaker
description: Bug-bounty validation-breaker. Generates 100 GitHub code-search patterns, collects up to 10k hits, filters to bounty-eligible (huntr AI/ML + HackerOne GitHub-scope), uses Gemma via OpenRouter to reason about parser/validator mismatches, builds and verifies a PoC, persists to Neon. Authorized security research.
version: 0.1.0
author: dhyabi2
license: MIT
metadata:
  hermes:
    tags: [security, bounty-hunting, bypass, validation, ssrf, prompt-injection]
prerequisites:
  env:
    - OPENROUTER_API_KEY
    - NEON_DATABASE_URL
    - GH_PAT
  python:
    - psycopg[binary]
---

# validation-breaker

**Authorized security research only.** This skill hunts for input-validation bypass bugs in bounty-eligible open-source repos on GitHub.

## What you do when invoked

Run EXACTLY one iteration. Do not loop yourself — a scheduler fires you hourly.

## Execute this Python script

Invoke the bash tool with this single command:

```bash
python3 - <<'PYEOF'
import importlib.util, os, sys, urllib.request, subprocess

# Ensure psycopg is available
try:
    import psycopg
except ImportError:
    subprocess.run([sys.executable, '-m', 'pip', 'install', '-q', 'psycopg[binary]'], check=True)

# Download and exec the pipeline script
SCRIPT_URL = 'https://raw.githubusercontent.com/dhyabi2/validation-breaker-state/main/scripts/iterate.py'
code = urllib.request.urlopen(SCRIPT_URL, timeout=30).read().decode()
exec(compile(code, 'iterate.py', 'exec'), {'__name__': '__main__'})
PYEOF
```

The script at `scripts/iterate.py` in the state repo does the full pipeline:

1. **Pattern generation** — picks ~100 fresh (lang, class, query) tuples from a ~95-entry master list, seeded by iteration timestamp. Dedups against `validation_breaker.patterns_tried`.

2. **GitHub code search** — authenticated via `GH_PAT`. Pulls up to 100 hits per pattern, sleeps 2.2s between calls to stay under the 30 req/min limit. Cap: 10,000 hits total or 14-minute budget.

3. **Bounty-eligibility filter** — `huntr.com/api/v2/bounties?status=disclosed` union with hardcoded HackerOne GitHub-repo-scope program list and a ~40-org AI/ML heuristic allowlist (huggingface, langchain-ai, anthropic, etc.). Repos not matching are dropped.

4. **Gemma analysis** — for each eligible target (up to 20 per iter, highest GitHub-search score first):
   - Fetch raw source from `raw.githubusercontent.com`
   - Send to `google/gemma-4-31b-it:free` via OpenRouter with a strict JSON-mode system prompt listing classic parser/validator mismatches (URL userinfo, unanchored regex, suffix-match-no-dot, case-fold gaps, deserialization, path join before normalize, prompt-injection filters).
   - Model returns: `{exploitable, class, validator_line, payload, verification_python, expected_marker, impact, confidence, reasoning}`.

5. **Local PoC verification** — write `verification_python` to a temp file, run `python3 <tmpfile>` with 30s timeout, check stdout for the `expected_marker` (default `VB_BYPASS_VERIFIED`). Only `verified == True` counts as a finding.

6. **Persistence**:
   - `validation_breaker.findings` — verified bypasses (iter, repo, path, validator_line, class, payload, verification_output, impact, bounty_program, bounty_url, confidence, reasoning)
   - `validation_breaker.misses` — dead ends with reason
   - `validation_breaker.patterns_tried` — pattern dedup
   - `validation_breaker.repos_scanned` — repo dedup
   - `validation_breaker.state` — iter_count and other scalars

7. **Repo-visible checkpoint** — writes `progress.log` and `LATEST.md` in the state repo so commits show the loop is alive.

## Invariants

- **No fabrication.** Verified = PoC printed the marker. Everything else is a miss.
- **No credentials leaked.** Tokens stay in env; never echo.
- **Budget.** 14 min wall-clock, then commit partial and exit clean.
- **Dedup.** State is persistent across iterations via Neon.

## Configuration

- `VB_MODEL` — override Gemma model id (default `google/gemma-4-31b-it:free`)
- `VB_MAX_HITS` — cap on total hits collected (default 10000)
- `VB_MAX_ANALYZE` — max targets sent to Gemma per iter (default 20)
- `VB_TIME_BUDGET` — seconds (default 840)

## Inspecting progress

- Commits: https://github.com/dhyabi2/validation-breaker-state/commits
- Findings: `psql $NEON_DATABASE_URL -c "SELECT repo, file_path, attack_class, impact, confidence FROM validation_breaker.findings ORDER BY id DESC LIMIT 20;"`
- Misses: same DB, `validation_breaker.misses`
