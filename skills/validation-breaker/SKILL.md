---
name: validation-breaker
description: Bug-bounty validation-breaker. Generates 100+ GitHub code-search patterns, collects up to 10k hits, filters to bounty-eligible (huntr AI/ML + HackerOne GitHub-scope), uses Gemma 4 31B IT via OpenRouter to reason about parser/validator mismatches, retries through Hermes on hard targets, verifies a PoC, persists to Neon. Authorized security research.
version: 0.2.0
author: dhyabi2
license: MIT
metadata:
  hermes:
    tags: [security, bounty-hunting, bypass, validation, ssrf, prompt-injection, poc-verification]
prerequisites:
  env:
    - OPENROUTER_API_KEY
    - NEON_DATABASE_URL
    - GH_PAT
    - VB_MODEL (default google/gemma-4-31b-it)
  python:
    - psycopg[binary]
---

# validation-breaker

**Authorized security research only.** Hunts input-validation bypass bugs in bounty-eligible open-source repos on GitHub. Runs ONE iteration per invocation; a scheduler fires hourly.

## Mission

Find code where external input flows into a security validator that is trivially bypassable (parser/validator mismatch, unanchored regex, suffix match without anchor, case/Unicode gap, path join before normalize, deserialization gate, unescaped prompt filter....many other). You mission is to break this security piece of code with maximum focus , find related dependencies that could mitigate have security measurement and have full knwoledge how to break it.

## What you do

Run `python /iterate.py`. That script lives in the container image; do not fetch it from the network. If the file is missing, abort — this means the container is mis-built.

```bash
python3 /iterate.py
```

That is the entirety of the skill. Everything else below is reference for WHY the script does what it does, and when you (as the Hermes agent on a deep-retry call) are invoked.

## When you are called as a second-opinion reasoner

`iterate.py` subprocess-invokes `/hermes/cli.py --query "<target+prior_attempt>" --quiet` when Gemma's first-pass analysis was either (a) `exploitable=false` or (b) produced a PoC that failed to verify. You are the deep-analysis retry path.

Your task on those invocations: **find a real, verifiable bypass that Gemma missed**, OR honestly confirm there is no exploitable gap. Return STRICT JSON with these fields:

```json
{
  "exploitable": true|false,
  "class": "one-word",
  "title": "short bypass title",
  "line_range": "Lx-Ly or null",
  "vulnerable_code": "10-20 lines of the relevant code block",
  "input_source": "where external input enters",
  "validation": "exact validator expression",
  "sink": "what resolves the input (requests.get, open, exec, …)",
  "reachability": "1-2 sentences on how request reaches sink",
  "bypass_payload": "concrete payload, or null",
  "verification_python": "self-contained stdlib-only python3 that prints VB_BYPASS_VERIFIED iff the payload works. No network. Null if cannot write one.",
  "expected_marker": "VB_BYPASS_VERIFIED",
  "impact": "RCE|SSRF-to-metadata|auth-bypass|path-traversal|prompt-injection|deserialization-rce|other",
  "severity": "critical|high|medium|low",
  "confidence": "high|medium|low",
  "explanation": "2-4 sentences on the mismatch",
  "suggested_fix": "1-2 sentences",
  "markdown": "full disclosure-ready writeup"
}
```

No fabrication. If the prior attempt was correct that there's no exploitable gap, set `exploitable=false` and explain WHY in `explanation`.

## Pipeline iterate.py executes

1. **Run record** — `INSERT INTO bounty_hunt.runs (started_at, status='running', note=model) RETURNING id`.

2. **Pattern generation** — picks up to 100 fresh `(lang, class, query, sev)` tuples from a 105-entry MASTER list. Dedups against `bounty_hunt.patterns` across prior runs. Writes picked patterns into that table.

3. **GitHub code search** — authenticated via `GH_PAT` (30 req/min; sleep 2.2s). Up to 100 hits/query × 100 queries = `VB_MAX_HITS=10000`. Writes each hit into `bounty_hunt.hits` as it arrives — visible live on the portal's `/live` page via SSE.

4. **Bounty-eligibility filter**:
   - `huntr.com/api/v2/bounties?status=disclosed` → disclosed-repo set (tier 3)
   - HackerOne hardcoded allowlist: 81 known-scope orgs (airbnb, gitlab-org, shopify, nodejs, mozilla, uber, cloudflare, stripe, hashicorp, …) — any repo under those orgs counts (tier 2)
   - AI-org allowlist: ~40 orgs (huggingface, langchain-ai, anthropic, openai, facebookresearch, …) → huntr-AI eligible (tier 2, ai_bonus 2)
   - Repos not on any list → discarded.

5. **Rank + targets** — sort eligible by `(tier, score, ai_bonus)`. Write top `VB_MAX_ANALYZE=20` into `bounty_hunt.targets` with `status='pending'`.

6. **Per-target Gemma analysis** — fetch raw source (max 40 KB), POST to `openrouter/v1/chat/completions` with `google/gemma-4-31b-it` in JSON-mode. System prompt lists classic parser/validator mismatches (URL userinfo, unanchored regex, suffix-match-no-dot, case/Unicode gap, deserialization, path join before normalize, prompt-injection filter gaps).

7. **Hermes retry** — if Gemma returned not-exploitable OR PoC failed to verify, subprocess `python /hermes/cli.py --query … --quiet` on the target. Budget: 3 retries per iter. When you are the agent here, you re-analyze with your full reasoning loop.

8. **Local PoC verification** — write `verification_python` to a temp file, `python3 <tmp>` (30s timeout). If stdout contains the `expected_marker` (default `VB_BYPASS_VERIFIED`), mark the target `bypass_found` and INSERT a full row into `bounty_hunt.findings`. Otherwise target status is `no_bypass` / `verify_failed` / `llm_failed` / `parse_failed` / `fetch_failed`.

9. **Finalize** — `UPDATE bounty_hunt.runs SET finished_at=NOW(), status='succeeded', note='hits=… eligible=… analyzed=… verified=… hermes_retries=…'`.

## Invariants (non-negotiable)

- **No fabrication.** Verified = the marker appeared in stdout on this runner. Anything else is a miss.
- **No credential leak.** `GH_PAT`, `OPENROUTER_API_KEY`, `NEON_DATABASE_URL` live in env only. Never echo, never commit.
- **Time budget 840s (14 min).** If stuck, commit partial state and exit clean.
- **Dedup.** Patterns and repos are tracked across iterations via the `bounty_hunt.patterns` and `bounty_hunt.targets` tables — do not re-analyze the same repo/path in later runs.

## Configuration env vars

- `VB_MODEL` — OpenRouter model id (default `google/gemma-4-31b-it` paid tier)
- `VB_MAX_HITS` — cap on total hits (default 10000)
- `VB_MAX_ANALYZE` — max targets per iter (default 20)
- `VB_TIME_BUDGET` — seconds (default 840)

## Observability

- Live SSE: https://bounty-hunt-portal.vercel.app/live — real-time run counts + delta events
- Runs index: https://bounty-hunt-portal.vercel.app/
- Findings: https://bounty-hunt-portal.vercel.app/findings
- Fly logs: `flyctl logs --app vb-hermes-dhyabi2`
- Raw SQL: `psql $NEON_DATABASE_URL -c "SELECT * FROM bounty_hunt.findings ORDER BY id DESC LIMIT 10;"`

## Schema (Neon, `bounty_hunt` schema)

```sql
runs     (id, started_at, finished_at, status, note)
hits     (id, run_id, pattern_id, repo, path, url, ingested_at)
patterns (run_id, pattern_id, query, language, sev)
targets  (id, run_id, hit_id, rank, score, tier, ai_bonus, sev, stars,
          pattern_id, repo, path, url, status)
findings (id, run_id, target_id, created_at, repo, path, line_range, title,
          bug_class, severity, status, prior_cve, vulnerable_code,
          input_source, validation, sink, reachability, bypass_payload,
          explanation, impact, poc, suggested_fix,
          disclosure_venue, report_url, markdown)
```

The Vercel portal reads these tables directly; any new finding appears on `/findings` within the 2s SSE polling window.
