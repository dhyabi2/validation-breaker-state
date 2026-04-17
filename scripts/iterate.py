#!/usr/bin/env python3
"""validation-breaker / bounty-hunt — one iteration.
Writes to the portal's bounty_hunt schema so the Vercel portal renders everything."""
import json, os, random, re, subprocess, tempfile, time, urllib.parse, urllib.request
import psycopg

OPENROUTER_KEY = os.environ['OPENROUTER_API_KEY']
DB_URL         = os.environ['NEON_DATABASE_URL']
GH_TOKEN       = os.environ['GH_PAT']
MODEL          = os.environ.get('VB_MODEL', 'google/gemma-4-31b-it')
MAX_HITS       = int(os.environ.get('VB_MAX_HITS', '10000'))
MAX_ANALYZE    = int(os.environ.get('VB_MAX_ANALYZE', '20'))
MAX_PATTERNS   = int(os.environ.get('VB_MAX_PATTERNS', '100'))
TIME_BUDGET    = int(os.environ.get('VB_TIME_BUDGET', '840'))
T0 = time.time()
DEBUG = os.environ.get('VB_DEBUG', '1') not in ('0','false','no','')
def over_budget(): return time.time() - T0 > TIME_BUDGET

def log(step, status, detail=''):
    print(f"{time.strftime('%H:%M:%S')} {step} {status} {detail}", flush=True)

_current_run_id = None
_current_target_id = None

def redact(s):
    if not s: return s
    s = str(s)
    for k in ('OPENROUTER_API_KEY','GH_PAT','NEON_DATABASE_URL'):
        v = os.environ.get(k,'')
        if v and len(v) > 8: s = s.replace(v, f'***{k}***')
    # also redact any Bearer token, Authorization headers, urlencoded user:pass
    import re as _re
    s = _re.sub(r'(Bearer\s+)[A-Za-z0-9_\-\.=+/]{8,}', r'\1***', s)
    s = _re.sub(r'(://[^/@\s]+:)[^@\s]+@', r'\1***@', s)
    return s

def debug(kind, endpoint=None, status_code=None, duration_ms=None, body=None):
    if not DEBUG: return
    try:
        preview = None
        if body is not None:
            if isinstance(body, (dict, list)): body = json.dumps(body)[:4000]
            elif isinstance(body, bytes):       body = body[:4000].decode('utf-8', errors='replace')
            preview = redact(str(body))[:4000]
        # use a short-lived connection to avoid clashing with the main cursor's transaction
        c = psycopg.connect(DB_URL, autocommit=True)
        cc = c.cursor()
        cc.execute("INSERT INTO bounty_hunt.debug_events(run_id, target_id, kind, endpoint, status_code, duration_ms, body_preview) VALUES(%s,%s,%s,%s,%s,%s,%s)",
                   (_current_run_id, _current_target_id, kind, redact(endpoint) if endpoint else None, status_code, duration_ms, preview))
        cc.close(); c.close()
    except Exception as e:
        print(f"[debug-fail] {e}", flush=True)

def http(method, url, headers=None, body=None, timeout=60):
    data = json.dumps(body).encode() if isinstance(body, (dict,list)) else body
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    debug('http_req', endpoint=f"{method} {url}", body=body if body else None)
    t = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            content = r.read()
            ms = int((time.time()-t)*1000)
            debug('http_resp', endpoint=url, status_code=r.status, duration_ms=ms, body=content)
            return r.status, content
    except urllib.error.HTTPError as e:
        content = e.read()
        ms = int((time.time()-t)*1000)
        debug('http_resp', endpoint=url, status_code=e.code, duration_ms=ms, body=content)
        return e.code, content
    except Exception as e:
        ms = int((time.time()-t)*1000)
        debug('http_err', endpoint=url, duration_ms=ms, body=repr(e))
        return 0, repr(e).encode()

GH_HDR = {'Authorization': f'Bearer {GH_TOKEN}', 'Accept': 'application/vnd.github.v3+json', 'User-Agent': 'vb-bot'}
OR_HDR = {'Authorization': f'Bearer {OPENROUTER_KEY}', 'Content-Type': 'application/json',
          'HTTP-Referer': 'https://bounty-hunt-portal.vercel.app', 'X-Title': 'validation-breaker'}

# ===== db =====
conn = psycopg.connect(DB_URL, autocommit=True)
cur = conn.cursor()

cur.execute("INSERT INTO bounty_hunt.runs(started_at, status, note) VALUES(NOW(), 'running', %s) RETURNING id",
            (f"model={MODEL}",))
run_id = cur.fetchone()[0]
_current_run_id = run_id
log('run', 'start', f'id={run_id} model={MODEL}')
debug('iter_start', body={'run_id': run_id, 'model': MODEL, 'max_patterns': MAX_PATTERNS, 'max_hits': MAX_HITS, 'max_analyze': MAX_ANALYZE, 'time_budget': TIME_BUDGET})

MASTER = [
    ('python','ssrf-suffix','"urlparse" "hostname" ".endswith(" language:Python',3),
    ('python','ssrf-suffix2','"urlparse" ".hostname" "in ALLOWED" language:Python',3),
    ('python','ssrf-parser','"urlparse" "netloc" "requests.get" language:Python',3),
    ('python','ssrf-loopback','"127.0.0.1" "not in" "hostname" language:Python',2),
    ('python','path-traversal','"os.path.join" "request." "open(" language:Python',2),
    ('python','path-normalize','"os.path.normpath" "request" "open" language:Python',3),
    ('python','unanchored-regex','"re.search" "host" "requests" language:Python',3),
    ('python','unanchored-match','"re.match" "allowed" language:Python',2),
    ('python','prompt-injection','"re.search" "ignore previous" language:Python',2),
    ('python','prompt-filter','"any(" "word in" "prompt" language:Python',2),
    ('python','unicode-gap','".lower()" "not in" "blocked" language:Python',2),
    ('python','suffix-endswith','".endswith(" "hostname" "raise" language:Python',3),
    ('python','yaml-load','"yaml.load(" "Loader=yaml.Loader" language:Python',4),
    ('python','pickle-load','"pickle.loads" "request" language:Python',4),
    ('python','sqli-format','".format(" "SELECT" "cursor.execute" language:Python',3),
    ('js','path-traversal','"path.join" "req.query" "sendFile" language:JavaScript',3),
    ('js','path-resolve','"path.resolve" "req.body" "readFile" language:JavaScript',3),
    ('js','ssrf-url','"new URL" ".hostname ===" language:JavaScript',3),
    ('js','ssrf-url-in','"new URL" ".hostname" "includes" language:JavaScript',3),
    ('js','prompt-injection','".match" "jailbreak" language:JavaScript',2),
    ('js','prompt-includes','".includes" "ignore" "instructions" language:JavaScript',2),
    ('js','unanchored-regex','"new RegExp" ".test(" "allowed" language:JavaScript',3),
    ('js','regex-host','"regex.test" "hostname" language:JavaScript',3),
    ('js','unicode-gap','".toLowerCase()" "includes" "host" language:JavaScript',2),
    ('js','deserialization','"JSON.parse" "req.body" "eval" language:JavaScript',4),
    ('js','node-vm','"new vm.Script" "req." language:JavaScript',4),
    ('js','child-exec','"child_process" "exec" "req.query" language:JavaScript',4),
    ('js','express-render','"res.render" "req.params" language:JavaScript',3),
    ('ts','path-traversal','"path.resolve" "req.params" "readFile" language:TypeScript',3),
    ('ts','ssrf-url','"new URL" "hostname" "fetch" language:TypeScript',3),
    ('ts','prompt-injection','"includes" "ignore" "instructions" language:TypeScript',2),
    ('ts','regex-hostname','"RegExp" "test" "hostname" language:TypeScript',3),
    ('ts','unicode-normalize','"normalize" "NFC" "compare" language:TypeScript',2),
    ('ts','class-transform','"class-transformer" "plainToInstance" language:TypeScript',3),
    ('ts','zod-parse','"z.string()" "url()" "fetch" language:TypeScript',3),
    ('ts','graphql-input','"InputType" "validate" "fetch" language:TypeScript',3),
    ('go','ssrf-parser','"url.Parse" ".Host" "http.Get" language:Go',3),
    ('go','ssrf-host-eq','"url.Parse" "Host ==" "httpClient" language:Go',3),
    ('go','path-traversal','"filepath.Join" "r.URL.Query" language:Go',3),
    ('go','path-clean','"filepath.Clean" "r.FormValue" "os.Open" language:Go',3),
    ('go','unanchored-regex','"regexp.MatchString" "host" language:Go',3),
    ('go','regex-find','"regexp.MustCompile" "FindString" "host" language:Go',3),
    ('go','deserialization','"json.Unmarshal" "r.Body" language:Go',2),
    ('go','gob-decode','"gob.NewDecoder" "r.Body" language:Go',4),
    ('go','unicode-gap','"strings.ToLower" "==" "allowed" language:Go',2),
    ('go','prompt-injection','"strings.Contains" "prompt" "ignore" language:Go',2),
    ('go','sql-fmt','"fmt.Sprintf" "SELECT" "db.Exec" language:Go',3),
    ('rust','unanchored-regex','"Regex::new" "is_match" "reqwest" language:Rust',3),
    ('rust','regex-find','"Regex::new" ".find" "host" language:Rust',3),
    ('rust','ssrf-url','"Url::parse" ".host_str" language:Rust',3),
    ('rust','path-traversal','"Path::new" "query" "read_to_string" language:Rust',3),
    ('rust','deserialization','"serde_json::from_str" "body" language:Rust',2),
    ('rust','bincode','"bincode::deserialize" "body" language:Rust',3),
    ('rust','unicode-gap','".to_lowercase" "==" language:Rust',2),
    ('rust','prompt-inject','".contains" "system" "prompt" language:Rust',2),
    ('rust','sql-format','"format!" "SELECT" "sqlx" language:Rust',3),
    ('java','deserialization','"ObjectInputStream" "readObject" language:Java',4),
    ('java','jackson-poly','"@JsonTypeInfo" "DefaultTyping" language:Java',4),
    ('java','ssrf-url','"new URL" ".getHost()" language:Java',3),
    ('java','path-traversal','"Paths.get" "getParameter" language:Java',3),
    ('java','file-traversal','"new File" "request.getParameter" language:Java',3),
    ('java','unanchored-regex','"Pattern.compile" ".matcher" "find()" language:Java',3),
    ('java','unicode-gap','".toLowerCase()" "equals" "allowed" language:Java',2),
    ('java','prompt-injection','".contains" "jailbreak" language:Java',2),
    ('java','spel-eval','"SpelExpressionParser" "parseExpression" language:Java',4),
    ('java','ognl','"Ognl.getValue" "request" language:Java',4),
    ('ruby','ssrf-url','"URI.parse" ".host" "Net::HTTP" language:Ruby',3),
    ('ruby','open-uri','"open(" "params" "URI" language:Ruby',4),
    ('ruby','path-traversal','"File.join" "params" "File.read" language:Ruby',3),
    ('ruby','send-method','".send(" "params" language:Ruby',4),
    ('ruby','unanchored-regex','"=~" "host" "http.get" language:Ruby',3),
    ('ruby','deserialization','"Marshal.load" "params" language:Ruby',4),
    ('ruby','yaml-load','"YAML.load" "params" language:Ruby',4),
    ('ruby','unicode-gap','".downcase" "==" language:Ruby',2),
    ('php','ssrf-parser','"parse_url" "host" "file_get_contents" language:PHP',3),
    ('php','curl-url','"parse_url" "CURLOPT_URL" language:PHP',3),
    ('php','path-traversal','"file_get_contents" "$_GET" language:PHP',3),
    ('php','include','"include(" "$_GET" language:PHP',4),
    ('php','unanchored-regex','"preg_match" "host" language:PHP',3),
    ('php','deserialization','"unserialize" "$_POST" language:PHP',4),
    ('php','phar','"phar://" "$_GET" language:PHP',4),
    ('php','unicode-gap','"strtolower" "==" "allowed" language:PHP',2),
    ('csharp','ssrf-uri','"new Uri" ".Host" "HttpClient" language:C#',3),
    ('csharp','path-combine','"Path.Combine" "Request." language:C#',3),
    ('csharp','unanchored-regex','"Regex.IsMatch" "host" language:C#',3),
    ('csharp','deserialization','"BinaryFormatter" "Deserialize" language:C#',4),
    ('csharp','json-typeless','"JsonConvert" "TypeNameHandling" language:C#',4),
    ('csharp','unicode-gap','".ToLower()" "==" "Allowed" language:C#',2),
    ('csharp','razor-compile','"Razor.Parse" "request" language:C#',4),
    ('kotlin','path-traversal','"File(" "request." "readText" language:Kotlin',3),
    ('kotlin','ssrf-url','"URL(" ".host" language:Kotlin',3),
    ('kotlin','unanchored-regex','"Regex(" ".containsMatchIn" language:Kotlin',3),
    ('kotlin','deserialization','"ObjectMapper" "readValue" language:Kotlin',2),
    ('swift','ssrf-url','"URL(string:" "host" language:Swift',3),
    ('swift','path-traversal','"FileManager" "contents" "request" language:Swift',3),
    # added to reach 100+
    ('python','xml-external','"etree" "parse" "request" language:Python',4),
    ('python','template-injection','"Template" "render" "request" language:Python',4),
    ('python','command-inj','"subprocess" "shell=True" "request" language:Python',4),
    ('js','open-redirect','"res.redirect" "req.query" language:JavaScript',2),
    ('js','eval-user','"eval(" "req." language:JavaScript',5),
    ('go','cmd-exec','"exec.Command" "r.FormValue" language:Go',4),
    ('rust','cmd-exec','"Command::new" "body" language:Rust',4),
    ('java','xxe','"DocumentBuilderFactory" "parse" "request" language:Java',4),
    ('php','lfi','"readfile" "$_GET" language:PHP',4),
    ('csharp','xxe','"XmlDocument" "Load" "Request" language:C#',4),
]

cur.execute("SELECT DISTINCT query FROM bounty_hunt.patterns")
tried = {r[0] for r in cur.fetchall()}
unused = [p for p in MASTER if p[2] not in tried]
random.seed(int(time.time()) ^ run_id)
picked = random.sample(unused, min(MAX_PATTERNS, len(unused))) if unused else random.sample(MASTER, min(MAX_PATTERNS, len(MASTER)))
log('patterns', 'ok', f'master={len(MASTER)} tried={len(tried)} picked={len(picked)}')

for (lang, cls, query, sev) in picked:
    pid = f"{lang}:{cls}"
    cur.execute("INSERT INTO bounty_hunt.patterns(run_id, pattern_id, query, language, sev) VALUES(%s,%s,%s,%s,%s)",
                (run_id, pid, query, lang, sev))

all_hits = []
for idx, (lang, cls, query, sev) in enumerate(picked):
    if over_budget() or len(all_hits) >= MAX_HITS:
        log('search', 'stop', f'idx={idx} hits={len(all_hits)}')
        break
    url = 'https://api.github.com/search/code?' + urllib.parse.urlencode({'q': query, 'per_page': 100})
    code, body = http('GET', url, headers=GH_HDR)
    if code == 200:
        d = json.loads(body)
        items = d.get('items', [])
        pid = f"{lang}:{cls}"
        for i in items:
            hit_url = i.get('html_url') or f"https://github.com/{i['repository']['full_name']}/blob/{i['sha']}/{i['path']}"
            cur.execute("INSERT INTO bounty_hunt.hits(run_id, pattern_id, repo, path, url, ingested_at) VALUES(%s,%s,%s,%s,%s,NOW()) RETURNING id",
                        (run_id, pid, i['repository']['full_name'], i['path'], hit_url))
            hit_id = cur.fetchone()[0]
            all_hits.append({
                'id': hit_id, 'repo': i['repository']['full_name'], 'path': i['path'], 'sha': i['sha'],
                'url': hit_url, 'score': float(i.get('score', 0) or 0), 'lang': lang, 'class': cls, 'sev': sev, 'pattern_id': pid,
            })
    elif code == 403:
        log('search', 'rate-limit', 'sleep 30s'); time.sleep(30)
    else:
        log('search', 'fail', f'code={code}')
    time.sleep(2.2)

log('search', 'done', f'hits={len(all_hits)}')

def fetch_huntr_repos():
    code, body = http('GET', 'https://huntr.com/api/v2/bounties?status=disclosed&limit=500',
                      headers={'User-Agent': 'vb-bot', 'Accept': 'application/json'})
    repos = set()
    if code == 200:
        try:
            d = json.loads(body)
            for b in d.get('bounties', d.get('data', [])):
                r = (b.get('repo') or {}).get('name') or b.get('repository')
                if r and '/' in r: repos.add(r.lower())
        except: pass
    return repos

H1_KNOWN_ORGS = {
    # well-known HackerOne programs with active GitHub scope (orgs; any repo under them is in scope)
    'airbnb','discourse','gitlab-org','mozilla','nextcloud','nodejs','phpmyadmin','shopify',
    'wordpress','facebook','meta-llama','facebookresearch','curl','uber','uber-go','spotify',
    'square','hackerone','getsentry','twilio','auth0','magento','grab','gitterhq','dropbox',
    'slackhq','yelp','zomato','bookingcom','mapbox','twitter','docker','kubernetes','cloudflare',
    'torproject','cisco','ibm','adobe','snapcore','snapchat','line','linecorp','basecamp',
    'gitlab','github','heroku','pinterest','paypal','ebay','lyft','verizonmedia','yahoo',
    'indeed-com','semrush','rockstargames','grammarly','zendesk','atlassian','bugcrowd',
    'asana','figma','intel','intercom','netflix','tesla','tinder','vimeo','xero','zapier',
    'zoomus','zoom','okta','salesforce','digitalocean','backblaze','plaid','stripe',
    'hashicorp','elastic','gitea','forgejo',
}
H1_KNOWN = set()  # full repo names override — kept for backward compat
AI_ORGS = {'huggingface','langchain-ai','openai','anthropic','google','meta-llama','nvidia','microsoft','ibm',
           'vllm-project','ray-project','mlflow','bentoml','triton-inference-server','gradio-app','streamlit',
           'kubeflow','feast-dev','mosaicml','bigscience','eleutherai','facebookresearch','pytorch','tensorflow',
           'onnx','ml-explore','unslothai','vllm','mlc-ai','ollama','guardrails-ai','llamaindex','pydantic',
           'langgraph','crewaiinc','giskard-ai','promptfoo','haystackai','comfyanonymous','automatic1111',
           'invoke-ai','scikit-learn','allenai','stability-ai','runwayml','vercel','nextauthjs'}

huntr_repos = fetch_huntr_repos()
def why_eligible(repo):
    r = repo.lower()
    org = r.split('/')[0]
    if r in huntr_repos: return ('huntr', f'https://huntr.com/repos/{r}', 3, 1)
    if r in H1_KNOWN or org in H1_KNOWN_ORGS: return ('hackerone', f'https://hackerone.com/{org}', 2, 0)
    if org in AI_ORGS: return ('huntr-ai', 'https://huntr.com/', 2, 2)
    return (None, None, 0, 0)

eligible = []
for h in all_hits:
    prog, url, tier, ai_bonus = why_eligible(h['repo'])
    if prog:
        h['program'], h['program_url'], h['tier'], h['ai_bonus'] = prog, url, tier, ai_bonus
        eligible.append(h)
log('filter', 'ok', f'huntr={len(huntr_repos)} eligible={len(eligible)}')

eligible.sort(key=lambda h: (h['tier'], h['score'], h['ai_bonus']), reverse=True)
targets = []
for rank, h in enumerate(eligible[:MAX_ANALYZE], start=1):
    cur.execute("""INSERT INTO bounty_hunt.targets(run_id, hit_id, rank, score, tier, ai_bonus, sev, stars, pattern_id, repo, path, url, status)
                   VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'pending') RETURNING id""",
                (run_id, h['id'], rank, h['score'], h['tier'], h['ai_bonus'], h['sev'], 0, h['pattern_id'],
                 h['repo'], h['path'], h['url']))
    tid = cur.fetchone()[0]
    h['target_id'] = tid
    targets.append(h)
log('targets', 'ok', f'created={len(targets)}')

SYSTEM_PROMPT = """You are a security researcher analyzing an open-source validator for bypass bugs.

MISSION: Find code where external input flows into a security validator that is trivially bypassable (parser/validator mismatch, unanchored regex, suffix match without anchor, case/Unicode gap, path join before normalize, deserialization gate, unescaped prompt filter....many other). You mission is to break this security piece of code with maximum focus , find related dependencies that could mitigate have security measurement and have full knwoledge how to break it.

Classic parser/validator mismatches to check:
- URL parser differential (urlparse vs requests, new URL vs fetch, url.Parse vs net/http) — payloads: http://evil.com#@internal/, http://evil.com\\@internal/, IPv6 zone, decimal/hex IP, trailing-dot host
- Unanchored regex (re.search vs re.fullmatch; Regex.IsMatch without ^$; preg_match without \\A\\z)
- Suffix match without dot prefix (.endswith('.evil.com') accepting 'attacker-evil.com')
- Case/Unicode gap (.lower() + == missing Turkish I, fullwidth, NFKC)
- Path join before normalize (path.join → readFile without resolve+startswith)
- Deserialization gates (pickle/yaml.Loader/readObject/unserialize on user input)
- Prompt-injection filter using substring/regex missing homoglyphs, base64, tool-chained injections

Respond STRICT JSON with these exact fields:
{
 "exploitable": true|false,
 "class": "one-word",
 "title": "short bypass title",
 "line_range": "Lx-Ly or null",
 "vulnerable_code": "10-20 lines of the relevant code block",
 "input_source": "where the external input enters (e.g. 'req.query.path')",
 "validation": "exact validator expression",
 "sink": "what resolves the input (e.g. 'requests.get', 'open', 'exec')",
 "reachability": "how request reaches the sink (1-2 sentences)",
 "bypass_payload": "concrete payload, or null",
 "verification_python": "self-contained stdlib-only python3 snippet that prints 'VB_BYPASS_VERIFIED' IFF the payload demonstrates the bypass. No network. Null if cannot write one.",
 "expected_marker": "VB_BYPASS_VERIFIED",
 "impact": "RCE|SSRF-to-metadata|auth-bypass|path-traversal|prompt-injection|deserialization-rce|other",
 "severity": "critical|high|medium|low",
 "confidence": "high|medium|low",
 "explanation": "2-4 sentence technical explanation",
 "suggested_fix": "1-2 sentences",
 "markdown": "full finding writeup suitable for a disclosure report"
}

No fabrication. If no exploitable gap, set exploitable=false and null the payload/verification fields."""

def hermes_deep_analyze(src, repo, path, prior_attempt):
    """Invoke Hermes CLI for a smarter second opinion. Returns parsed JSON or None."""
    prompt = (f"You are a senior security researcher. A previous fast analysis was inconclusive:\n"
              f"prior: {json.dumps(prior_attempt)[:1500]}\n\n"
              f"Re-analyze this validator carefully. Find a REAL verifiable bypass.\n"
              f"File: {repo}::{path}\n\n```\n{src[:20000]}\n```\n\n"
              f"Return STRICT JSON with fields exploitable, class, title, line_range, vulnerable_code, "
              f"input_source, validation, sink, reachability, bypass_payload, verification_python, "
              f"expected_marker, impact, severity, confidence, explanation, suggested_fix, markdown. "
              f"verification_python must print 'VB_BYPASS_VERIFIED' to stdout iff the payload works. "
              f"No fabrication — if there is no real bypass, set exploitable=false.")
    debug('hermes_req', endpoint='/hermes/cli.py', body={'repo': repo, 'path': path, 'prompt_len': len(prompt)})
    t = time.time()
    try:
        r = subprocess.run(
            ['python', '/hermes/cli.py', '--query', prompt, '--quiet'],
            capture_output=True, text=True, timeout=180,
            env={**os.environ, 'HOME': '/root'}
        )
        out = (r.stdout or '') + (r.stderr or '')
        ms = int((time.time()-t)*1000)
        debug('hermes_resp', endpoint='/hermes/cli.py', duration_ms=ms, status_code=r.returncode, body=out[:4000])
        m = re.search(r'\{[\s\S]*\}', out)
        if m:
            return json.loads(m.group(0))
    except Exception as e:
        debug('hermes_err', body=repr(e)[:500])
        log('hermes', 'fail', repr(e)[:100])
    return None

def verify_poc(verification_python, expected_marker='VB_BYPASS_VERIFIED'):
    if not verification_python: return False, 'no snippet'
    with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False) as f:
        f.write(verification_python); script = f.name
    try:
        r = subprocess.run(['python3', script], capture_output=True, text=True, timeout=30)
        out = (r.stdout or '') + '\n--STDERR--\n' + (r.stderr or '')
        return (expected_marker in (r.stdout or '')), out
    except Exception as e:
        return False, f'exec error: {e}'
    finally:
        try: os.unlink(script)
        except: pass

analyzed = 0; verified = 0; hermes_retries = 0; MAX_HERMES_RETRIES = 3
for target in targets:
    if over_budget(): break
    analyzed += 1
    _current_target_id = target['target_id']
    cur.execute("UPDATE bounty_hunt.targets SET status='fetching', started_at=NOW() WHERE id=%s", (target['target_id'],))
    debug('target_start', body={'target_id': target['target_id'], 'repo': target['repo'], 'path': target['path'], 'pattern': target['pattern_id']})
    raw_url = f'https://raw.githubusercontent.com/{target["repo"]}/{target["sha"]}/{target["path"]}'
    code, body = http('GET', raw_url, headers=GH_HDR)
    if code != 200:
        cur.execute("UPDATE bounty_hunt.targets SET status='fetch_failed' WHERE id=%s", (target['target_id'],))
        continue
    src = body.decode('utf-8', errors='replace')[:40000]
    cur.execute("UPDATE bounty_hunt.targets SET status='analyzing', source_preview=%s WHERE id=%s",
                (src[:8000], target['target_id']))
    user_msg = f"File: {target['repo']}::{target['path']}\nBounty: {target['program']}\nPattern: {target['pattern_id']}\n\n```\n{src}\n```\n\nFind the bypass."
    or_body = {'model': MODEL, 'messages': [{'role':'system','content':SYSTEM_PROMPT},{'role':'user','content':user_msg}],
               'temperature': 0.2, 'max_tokens': 2500, 'response_format': {'type':'json_object'}}
    code, body = http('POST', 'https://openrouter.ai/api/v1/chat/completions', headers=OR_HDR, body=or_body, timeout=180)
    if code != 200:
        cur.execute("UPDATE bounty_hunt.targets SET status='llm_failed' WHERE id=%s", (target['target_id'],))
        log('llm', 'fail', f'code={code}')
        continue
    try:
        resp = json.loads(body)
        content = resp['choices'][0]['message']['content']
        content = re.sub(r'^```(?:json)?\s*|\s*```$', '', content.strip(), flags=re.MULTILINE)
        a = json.loads(content)
        debug('llm_parsed', body={'exploitable': a.get('exploitable'), 'class': a.get('class'), 'confidence': a.get('confidence'), 'title': a.get('title'), 'has_payload': bool(a.get('bypass_payload')), 'has_verification': bool(a.get('verification_python'))})
        cur.execute("UPDATE bounty_hunt.targets SET analyzed_at=NOW() WHERE id=%s", (target['target_id'],))
    except Exception as e:
        debug('llm_parse_fail', body=repr(e) + ' :: raw=' + (content[:1000] if 'content' in dir() else '?'))
        cur.execute("UPDATE bounty_hunt.targets SET status='parse_failed' WHERE id=%s", (target['target_id'],))
        continue

    needs_retry = not a.get('exploitable') or not a.get('verification_python') or not a.get('bypass_payload')
    ok = False; out = ''
    if not needs_retry:
        ok, out = verify_poc(a.get('verification_python'), a.get('expected_marker') or 'VB_BYPASS_VERIFIED')

    # Hermes retry path: if Gemma said not-exploitable OR its PoC failed to verify,
    # invoke Hermes CLI for a deeper second opinion (up to 3 retries per iter).
    if (needs_retry or not ok) and hermes_retries < MAX_HERMES_RETRIES:
        hermes_retries += 1
        log('hermes', 'retry', f'{target["repo"]} attempt={hermes_retries}')
        h = hermes_deep_analyze(src, target['repo'], target['path'], a)
        if h and h.get('exploitable') and h.get('verification_python') and h.get('bypass_payload'):
            h_ok, h_out = verify_poc(h.get('verification_python'), h.get('expected_marker') or 'VB_BYPASS_VERIFIED')
            if h_ok:
                a = h; ok = True; out = h_out
                log('hermes', 'bypass', f'{target["repo"]} hermes found what gemma missed')

    if not ok:
        cur.execute("UPDATE bounty_hunt.targets SET status=%s WHERE id=%s",
                    ('no_bypass' if needs_retry else 'verify_failed', target['target_id']))
        continue

    if True:  # verified
        verified += 1
        cur.execute("""INSERT INTO bounty_hunt.findings
            (run_id, target_id, created_at, repo, path, line_range, title, bug_class, severity, status,
             vulnerable_code, input_source, validation, sink, reachability,
             bypass_payload, explanation, impact, poc, suggested_fix,
             disclosure_venue, report_url, markdown)
            VALUES(%s,%s,NOW(),%s,%s,%s,%s,%s,%s,'confirmed',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (run_id, target['target_id'], target['repo'], target['path'], a.get('line_range'),
             a.get('title') or f"{a.get('class','bypass')} in {target['repo']}",
             a.get('class'), a.get('severity'),
             a.get('vulnerable_code'), a.get('input_source'), a.get('validation'), a.get('sink'), a.get('reachability'),
             a.get('bypass_payload') or '', a.get('explanation'), a.get('impact'),
             out[:8000], a.get('suggested_fix'),
             target['program'], target['program_url'], a.get('markdown')))
        cur.execute("UPDATE bounty_hunt.targets SET status='bypass_found' WHERE id=%s", (target['target_id'],))
        log('FINDING', 'verified', f'{target["repo"]}:{target["path"]} {a.get("class")}')

cur.execute("UPDATE bounty_hunt.runs SET finished_at=NOW(), status='succeeded', note=%s WHERE id=%s",
            (f"hits={len(all_hits)} eligible={len(eligible)} analyzed={analyzed} verified={verified} hermes_retries={hermes_retries}", run_id))
debug('iter_done', body={'hits': len(all_hits), 'eligible': len(eligible), 'analyzed': analyzed, 'verified': verified, 'hermes_retries': hermes_retries, 'elapsed_s': int(time.time()-T0)})
cur.close(); conn.close()
print(f"\niter run_id={run_id}: {len(all_hits)} hits, {len(eligible)} eligible, {analyzed} analyzed, {verified} verified")
