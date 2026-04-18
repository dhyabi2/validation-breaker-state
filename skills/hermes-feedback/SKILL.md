---
name: hermes-feedback
description: Submit, list, and triage feedback about the Hermes agent itself (bugs, skill gaps, prompt weaknesses, UX) against the bounty-hunt-portal feedback API. Stdlib-only — uses urllib and json; no external dependencies. Use whenever the user or you notice something to improve in the agent, a skill, a prompt, or the iterate.py pipeline.
version: 1.0.0
author: dhyabi2
license: MIT
metadata:
  hermes:
    tags: [feedback, triage, self-improvement, portal, api]
prerequisites:
  env:
    - PORTAL_PASSWORD
---

# hermes-feedback

Write reviewable notes about what the agent should improve next. Submitted items persist in Neon (`bounty_hunt.hermes_feedback`) and render at https://bounty-hunt-portal.vercel.app/feedback so no observation is lost between sessions.

## When to use this skill

- You just failed a task because a skill was missing, wrong, or unclear → submit `category=skill`.
- A pipeline step produced a false positive / false negative you cannot fix in this session → `category=bug`.
- The user asked a question that revealed a UX gap in the portal or the CLI → `category=ux`.
- You noticed the prompt you got back from Gemma/LLM was under-constrained → `category=prompt`.
- An iter was slower than it should be or retried excessively → `category=perf`.
- You thought of a feature that would make the next session better → `category=idea`.

Always link the evidence: `run_id`, `target_id`, or `finding_id` if any; concrete repos/paths in `body`.

## Endpoint

Base: `https://bounty-hunt-portal.vercel.app`

Auth: the portal is password-gated. `PORTAL_PASSWORD` is injected as an env var on the container; call `/api/login` once per session to get the `bh_auth` cookie, then include it in every subsequent call.

## Copy-paste client (stdlib only — no requests/httpx)

```python
import json, os, urllib.request, urllib.error

BASE = "https://bounty-hunt-portal.vercel.app"
PW   = os.environ["PORTAL_PASSWORD"]

_cookie = None
def _login():
    global _cookie
    if _cookie:
        return _cookie
    req = urllib.request.Request(
        f"{BASE}/api/login",
        data=json.dumps({"password": PW}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        raw = r.headers.get("set-cookie") or ""
    # Set-Cookie may be a single header; take the first k=v pair
    _cookie = raw.split(";", 1)[0] if raw else ""
    if not _cookie:
        raise RuntimeError("login failed (no cookie)")
    return _cookie

def _req(method, path, body=None):
    hdr = {"Cookie": _login(), "Accept": "application/json"}
    data = None
    if body is not None:
        hdr["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    req = urllib.request.Request(f"{BASE}{path}", data=data, method=method, headers=hdr)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")

# ===== Public helpers =====

def submit_feedback(
    title,
    body="",
    category="idea",          # bug | ux | idea | perf | skill | prompt | model | other
    severity="medium",        # critical | high | medium | low
    priority="p2",            # p0 | p1 | p2 | p3
    tags=None,                # list[str], ≤20 items × ≤40 chars
    run_id=None,              # int, optional (references bounty_hunt.runs.id)
    target_id=None,           # int, optional
    finding_id=None,          # int, optional
    author="hermes",
):
    """POST /api/feedback → returns (status_code, {ok, id, created_at} | {ok:false, error})."""
    payload = {
        "title": title, "body": body,
        "category": category, "severity": severity, "priority": priority,
        "author": author,
    }
    if tags:        payload["tags"] = list(tags)
    if run_id:      payload["run_id"] = int(run_id)
    if target_id:   payload["target_id"] = int(target_id)
    if finding_id:  payload["finding_id"] = int(finding_id)
    return _req("POST", "/api/feedback", payload)

def list_feedback(status=None, category=None, limit=50):
    """GET /api/feedback → (200, {ok, rows, counts})."""
    q = []
    if status:   q.append(f"status={urllib.parse.quote(status)}")
    if category: q.append(f"category={urllib.parse.quote(category)}")
    q.append(f"limit={int(limit)}")
    return _req("GET", "/api/feedback?" + "&".join(q))

def update_feedback(feedback_id, status=None, priority=None):
    """PATCH /api/feedback → (200, {ok, id, status, priority, updated_at})."""
    payload = {"id": int(feedback_id)}
    if status:   payload["status"] = status
    if priority: payload["priority"] = priority
    return _req("PATCH", "/api/feedback", payload)
```

## Examples

**Flag a skill gap after a failed iteration:**

```python
submit_feedback(
    title="iterate.py hermes retry never finds deserialization bypasses",
    body=("Last 3 iters: Gemma said not-exploitable on pickle.loads(user_input) in "
          "langchain-ai/langchain. Hermes retry concurred. Known-vulnerable pattern "
          "(CVE-2024-28088 style). Either the retry prompt is too cautious or the "
          "PoC template doesn't handle deserialization well."),
    category="skill",
    severity="high",
    priority="p1",
    run_id=42,
    finding_id=None,
    tags=["deserialization", "gemma", "retry-loop"],
)
```

**Report a portal bug:**

```python
submit_feedback(
    title="/current page shows stale target after iter ends",
    body="After iter_done event fires, target_id is still analyzing. Expected: clear or show 'idle'.",
    category="bug", severity="medium", priority="p2", tags=["portal","sse"]
)
```

**Query the open queue before picking work:**

```python
code, resp = list_feedback(status="open")
for r in sorted(resp["rows"], key=lambda r: ("p0","p1","p2","p3").index(r["priority"])):
    print(r["priority"], r["category"], "#"+str(r["id"]), r["title"])
```

**Triage an existing item you just addressed:**

```python
update_feedback(42, status="in_progress", priority="p1")
# …do the work…
update_feedback(42, status="done")
```

## Validation rules (enforced server-side)

| Field | Constraint |
|-------|-----------|
| `title` | required, string ≤ 200 chars |
| `body`  | optional, string ≤ 20000 chars |
| `category` | one of `bug,ux,idea,perf,skill,prompt,model,other` |
| `severity` | one of `critical,high,medium,low` |
| `priority` | one of `p0,p1,p2,p3` |
| `status` (PATCH only) | one of `open,triaged,planned,in_progress,done,wontfix,duplicate` |
| `author` | string ≤ 100, default `anonymous` (set this to `hermes` when the agent posts) |
| `tags` | array of strings, ≤ 20 items, each ≤ 40 chars |

Errors come back as `{"ok": false, "error": "…"}` with HTTP 400/401/404.

## Discipline

- **One feedback = one actionable improvement.** If a single failure implies two fixes, file two items.
- **Cite evidence by ID.** `run_id`/`target_id`/`finding_id` point the reader back to the raw data. Body without IDs is a note; body with IDs is a ticket.
- **Don't duplicate.** Call `list_feedback(category=…)` first; if you see the same idea, skip or PATCH the existing one with a higher priority instead.
- **Never post secrets.** Tokens, DB URLs, passwords — never in `title`/`body`/`tags`.
- **Default priority `p2`.** Escalate to `p1` only when something is wrong right now; `p0` when the agent is effectively broken.
