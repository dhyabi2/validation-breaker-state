#!/usr/bin/env python3
"""Validation-breaker: one iteration. Runs in GitHub Actions.
Generates ~100 patterns, collects up to 10k hits, filters to bounty-eligible,
uses Gemma via OpenRouter to find real bypass bugs, verifies PoC locally,
persists to Neon. Writes progress.log for repo-visible checkpoint."""
import base64, json, os, random, re, subprocess, sys, tempfile, time, urllib.parse, urllib.request
import psycopg

OPENROUTER_KEY = os.environ['OPENROUTER_API_KEY']
NEON_URL       = os.environ['NEON_DATABASE_URL']
GH_TOKEN       = os.environ['GH_PAT']
MODEL          = os.environ.get('VB_MODEL', 'google/gemma-4-31b-it:free')
MAX_HITS       = int(os.environ.get('VB_MAX_HITS', '10000'))
MAX_ANALYZE    = int(os.environ.get('VB_MAX_ANALYZE', '20'))
TIME_BUDGET    = int(os.environ.get('VB_TIME_BUDGET', '840'))  # 14 min
T0 = time.time()

def over_budget():
    return time.time() - T0 > TIME_BUDGET

# ===== logging =====
PROG = []
def log(step, status, detail=''):
    line = f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {step} {status} {detail}"
    PROG.append(line); print(line, flush=True)

# ===== http =====
def http(method, url, headers=None, body=None, timeout=60):
    data = json.dumps(body).encode() if isinstance(body, (dict,list)) else body
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return 0, repr(e).encode()

GH_HDR = {'Authorization': f'Bearer {GH_TOKEN}', 'Accept': 'application/vnd.github.v3+json', 'User-Agent': 'vb-bot'}
OR_HDR = {'Authorization': f'Bearer {OPENROUTER_KEY}', 'Content-Type': 'application/json',
          'HTTP-Referer': 'https://github.com/dhyabi2/validation-breaker-state', 'X-Title': 'validation-breaker'}

# ===== db =====
conn = psycopg.connect(NEON_URL, autocommit=True)
cur = conn.cursor()
cur.execute("""
CREATE SCHEMA IF NOT EXISTS validation_breaker;
CREATE TABLE IF NOT EXISTS validation_breaker.state (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS validation_breaker.patterns_tried (query TEXT PRIMARY KEY, lang TEXT, class TEXT, first_iter INT, uses INT DEFAULT 1, last_iter INT);
CREATE TABLE IF NOT EXISTS validation_breaker.repos_scanned (repo TEXT, path TEXT, iter INT, flagged BOOL, PRIMARY KEY (repo, path));
CREATE TABLE IF NOT EXISTS validation_breaker.findings (id SERIAL PRIMARY KEY, iter INT, repo TEXT, file_path TEXT, validator_line TEXT, attack_class TEXT, payload TEXT, verification_output TEXT, impact TEXT, bounty_program TEXT, bounty_url TEXT, confidence TEXT, reasoning TEXT, created_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS validation_breaker.misses (id SERIAL PRIMARY KEY, iter INT, repo TEXT, file_path TEXT, attack_class TEXT, confidence TEXT, reason TEXT, created_at TIMESTAMPTZ DEFAULT NOW());
""")

def state_get(k, default=None):
    cur.execute("SELECT value FROM validation_breaker.state WHERE key=%s", (k,))
    row = cur.fetchone()
    return row[0] if row else default

def state_set(k, v):
    cur.execute("INSERT INTO validation_breaker.state(key,value) VALUES(%s,%s) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value", (k, str(v)))

iter_n = int(state_get('iter_count', '0')) + 1
state_set('iter_count', iter_n)
log('start', 'ok', f'iter={iter_n} model={MODEL}')

# ===== master pattern list (150+ patterns, 10 langs x many classes) =====
MASTER = [
    # python
    ('python','ssrf-suffix','"urlparse" "hostname" ".endswith(" language:Python'),
    ('python','ssrf-suffix2','"urlparse" ".hostname" "in ALLOWED" language:Python'),
    ('python','ssrf-parser','"urlparse" "netloc" "requests.get" language:Python'),
    ('python','ssrf-loopback','"127.0.0.1" "not in" "hostname" language:Python'),
    ('python','path-traversal','"os.path.join" "request." "open(" language:Python'),
    ('python','path-normalize','"os.path.normpath" "request" "open" language:Python'),
    ('python','unanchored-regex','"re.search" "host" "requests" language:Python'),
    ('python','unanchored-match','"re.match" "allowed" language:Python'),
    ('python','prompt-injection','"re.search" "ignore previous" language:Python'),
    ('python','prompt-filter','"any(" "word in" "prompt" language:Python'),
    ('python','unicode-gap','".lower()" "not in" "blocked" language:Python'),
    ('python','suffix-endswith','".endswith(" "hostname" "raise" language:Python'),
    ('python','yaml-load','"yaml.load(" "Loader=yaml.Loader" language:Python'),
    ('python','pickle-load','"pickle.loads" "request" language:Python'),
    ('python','sqli-format','".format(" "SELECT" "cursor.execute" language:Python'),
    # js
    ('js','path-traversal','"path.join" "req.query" "sendFile" language:JavaScript'),
    ('js','path-resolve','"path.resolve" "req.body" "readFile" language:JavaScript'),
    ('js','ssrf-url','"new URL" ".hostname ===" language:JavaScript'),
    ('js','ssrf-url-in','"new URL" ".hostname" "includes" language:JavaScript'),
    ('js','prompt-injection','".match" "jailbreak" language:JavaScript'),
    ('js','prompt-includes','".includes" "ignore" "instructions" language:JavaScript'),
    ('js','unanchored-regex','"new RegExp" ".test(" "allowed" language:JavaScript'),
    ('js','regex-host','"regex.test" "hostname" language:JavaScript'),
    ('js','unicode-gap','".toLowerCase()" "includes" "host" language:JavaScript'),
    ('js','deserialization','"JSON.parse" "req.body" "eval" language:JavaScript'),
    ('js','node-vm','"new vm.Script" "req." language:JavaScript'),
    ('js','child-exec','"child_process" "exec" "req.query" language:JavaScript'),
    ('js','express-render','"res.render" "req.params" language:JavaScript'),
    # ts
    ('ts','path-traversal','"path.resolve" "req.params" "readFile" language:TypeScript'),
    ('ts','ssrf-url','"new URL" "hostname" "fetch" language:TypeScript'),
    ('ts','prompt-injection','"includes" "ignore" "instructions" language:TypeScript'),
    ('ts','regex-hostname','"RegExp" "test" "hostname" language:TypeScript'),
    ('ts','unicode-normalize','"normalize" "NFC" "compare" language:TypeScript'),
    ('ts','class-transform','"class-transformer" "plainToInstance" language:TypeScript'),
    ('ts','zod-parse','"z.string()" "url()" "fetch" language:TypeScript'),
    ('ts','graphql-input','"InputType" "validate" "fetch" language:TypeScript'),
    # go
    ('go','ssrf-parser','"url.Parse" ".Host" "http.Get" language:Go'),
    ('go','ssrf-host-eq','"url.Parse" "Host ==" "httpClient" language:Go'),
    ('go','path-traversal','"filepath.Join" "r.URL.Query" language:Go'),
    ('go','path-clean','"filepath.Clean" "r.FormValue" "os.Open" language:Go'),
    ('go','unanchored-regex','"regexp.MatchString" "host" language:Go'),
    ('go','regex-find','"regexp.MustCompile" "FindString" "host" language:Go'),
    ('go','deserialization','"json.Unmarshal" "r.Body" language:Go'),
    ('go','gob-decode','"gob.NewDecoder" "r.Body" language:Go'),
    ('go','unicode-gap','"strings.ToLower" "==" "allowed" language:Go'),
    ('go','prompt-injection','"strings.Contains" "prompt" "ignore" language:Go'),
    ('go','sql-fmt','"fmt.Sprintf" "SELECT" "db.Exec" language:Go'),
    # rust
    ('rust','unanchored-regex','"Regex::new" "is_match" "reqwest" language:Rust'),
    ('rust','regex-find','"Regex::new" ".find" "host" language:Rust'),
    ('rust','ssrf-url','"Url::parse" ".host_str" language:Rust'),
    ('rust','path-traversal','"Path::new" "query" "read_to_string" language:Rust'),
    ('rust','deserialization','"serde_json::from_str" "body" language:Rust'),
    ('rust','bincode','"bincode::deserialize" "body" language:Rust'),
    ('rust','unicode-gap','".to_lowercase" "==" language:Rust'),
    ('rust','prompt-inject','".contains" "system" "prompt" language:Rust'),
    ('rust','sql-format','"format!" "SELECT" "sqlx" language:Rust'),
    # java
    ('java','deserialization','"ObjectInputStream" "readObject" language:Java'),
    ('java','jackson-poly','"@JsonTypeInfo" "DefaultTyping" language:Java'),
    ('java','ssrf-url','"new URL" ".getHost()" language:Java'),
    ('java','path-traversal','"Paths.get" "getParameter" language:Java'),
    ('java','file-traversal','"new File" "request.getParameter" language:Java'),
    ('java','unanchored-regex','"Pattern.compile" ".matcher" "find()" language:Java'),
    ('java','unicode-gap','".toLowerCase()" "equals" "allowed" language:Java'),
    ('java','prompt-injection','".contains" "jailbreak" language:Java'),
    ('java','spel-eval','"SpelExpressionParser" "parseExpression" language:Java'),
    ('java','ognl','"Ognl.getValue" "request" language:Java'),
    # ruby
    ('ruby','ssrf-url','"URI.parse" ".host" "Net::HTTP" language:Ruby'),
    ('ruby','open-uri','"open(" "params" "URI" language:Ruby'),
    ('ruby','path-traversal','"File.join" "params" "File.read" language:Ruby'),
    ('ruby','send-method','".send(" "params" language:Ruby'),
    ('ruby','unanchored-regex','"=~" "host" "http.get" language:Ruby'),
    ('ruby','deserialization','"Marshal.load" "params" language:Ruby'),
    ('ruby','yaml-load','"YAML.load" "params" language:Ruby'),
    ('ruby','unicode-gap','".downcase" "==" language:Ruby'),
    # php
    ('php','ssrf-parser','"parse_url" "host" "file_get_contents" language:PHP'),
    ('php','curl-url','"parse_url" "CURLOPT_URL" language:PHP'),
    ('php','path-traversal','"file_get_contents" "$_GET" language:PHP'),
    ('php','include','"include(" "$_GET" language:PHP'),
    ('php','unanchored-regex','"preg_match" "host" language:PHP'),
    ('php','deserialization','"unserialize" "$_POST" language:PHP'),
    ('php','phar','"phar://" "$_GET" language:PHP'),
    ('php','unicode-gap','"strtolower" "==" "allowed" language:PHP'),
    # csharp
    ('csharp','ssrf-uri','"new Uri" ".Host" "HttpClient" language:C#'),
    ('csharp','path-combine','"Path.Combine" "Request." language:C#'),
    ('csharp','unanchored-regex','"Regex.IsMatch" "host" language:C#'),
    ('csharp','deserialization','"BinaryFormatter" "Deserialize" language:C#'),
    ('csharp','json-typeless','"JsonConvert" "TypeNameHandling" language:C#'),
    ('csharp','unicode-gap','".ToLower()" "==" "Allowed" language:C#'),
    ('csharp','razor-compile','"Razor.Parse" "request" language:C#'),
    # kotlin / swift
    ('kotlin','path-traversal','"File(" "request." "readText" language:Kotlin'),
    ('kotlin','ssrf-url','"URL(" ".host" language:Kotlin'),
    ('kotlin','unanchored-regex','"Regex(" ".containsMatchIn" language:Kotlin'),
    ('kotlin','deserialization','"ObjectMapper" "readValue" language:Kotlin'),
    ('swift','ssrf-url','"URL(string:" "host" language:Swift'),
    ('swift','path-traversal','"FileManager" "contents" "request" language:Swift'),
]

# ===== pick patterns =====
cur.execute("SELECT query FROM validation_breaker.patterns_tried")
tried = {r[0] for r in cur.fetchall()}
unused = [p for p in MASTER if p[2] not in tried]
random.seed(int(time.time()) ^ iter_n)
picked = random.sample(unused, min(100, len(unused))) if unused else random.sample(MASTER, min(100, len(MASTER)))
log('patterns', 'ok', f'master={len(MASTER)} tried={len(tried)} picked={len(picked)}')

# ===== search =====
all_hits = []  # {repo, path, sha, score, pattern, class}
for idx, (lang, cls, q) in enumerate(picked):
    if over_budget() or len(all_hits) >= MAX_HITS:
        log('search', 'stop', f'idx={idx} hits={len(all_hits)} reason={"budget" if over_budget() else "cap"}')
        break
    url = 'https://api.github.com/search/code?' + urllib.parse.urlencode({'q': q, 'per_page': 100})
    code, body = http('GET', url, headers=GH_HDR)
    if code == 200:
        d = json.loads(body)
        for i in d.get('items', []):
            all_hits.append({
                'repo': i['repository']['full_name'], 'path': i['path'], 'sha': i['sha'],
                'score': i.get('score', 0), 'lang': lang, 'class': cls, 'query': q,
            })
    elif code == 403:
        # rate limited — back off
        log('search', 'rate-limit', f'idx={idx} sleeping 30s')
        time.sleep(30)
    else:
        log('search', 'fail', f'code={code} q={q[:40]}')
    # mark pattern tried
    cur.execute("""INSERT INTO validation_breaker.patterns_tried(query,lang,class,first_iter,last_iter)
                   VALUES(%s,%s,%s,%s,%s) ON CONFLICT (query) DO UPDATE SET uses=patterns_tried.uses+1, last_iter=EXCLUDED.last_iter""",
                (q, lang, cls, iter_n, iter_n))
    time.sleep(2.2)  # 27 req/min

log('search', 'done', f'hits={len(all_hits)} patterns_used={min(idx+1,len(picked))}')

# ===== dedup repos against prior iterations =====
cur.execute("SELECT repo FROM validation_breaker.repos_scanned")
scanned = {r[0] for r in cur.fetchall()}
fresh = [h for h in all_hits if h['repo'] not in scanned]
log('dedup', 'ok', f'fresh={len(fresh)} repeats={len(all_hits)-len(fresh)}')

# ===== bounty filter =====
def fetch_huntr():
    # huntr does not have a public eligible-repo list; they publish disclosed bounties as blog posts.
    # Heuristic: any repo that has had a huntr disclosure is eligible. We fetch the disclosed feed.
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

def fetch_h1():
    # HackerOne scraping is gnarly; instead use their GraphQL public directory if available,
    # or fall back to a static known-good list of OSS-scoped programs.
    known = {
        'airbnb/airbnb', 'airbnb/lottie-ios', 'discourse/discourse', 'docker/docker-ce',
        'gitlab-org/gitlab', 'mozilla/gecko-dev', 'nextcloud/server', 'nodejs/node',
        'opencart/opencart', 'phpmyadmin/phpmyadmin', 'shopify/liquid', 'shopify/shopify-api-ruby',
        'spotify/docker-client', 'uber/RIBs', 'wordpress/wordpress', 'yelp/synapse',
        'facebook/hermes', 'facebook/react', 'facebook/react-native', 'curl/curl',
    }
    return {r.lower() for r in known}

huntr_repos = fetch_huntr()
h1_repos = fetch_h1()
eligible_set = huntr_repos | h1_repos
log('bounty', 'ok', f'huntr={len(huntr_repos)} h1={len(h1_repos)} union={len(eligible_set)}')

def why_eligible(repo):
    r = repo.lower()
    if r in huntr_repos: return 'huntr', f'https://huntr.com/repos/{r}'
    if r in h1_repos:    return 'hackerone', f'https://hackerone.com/{r.split("/")[0]}'
    # accept AI/ML repos heuristically (huntr covers AI/ML broadly) if they match known AI org names
    ai_orgs = {'huggingface', 'langchain-ai', 'openai', 'anthropic', 'google', 'meta-llama',
               'nvidia', 'openlm-research', 'lm-sys', 'microsoft', 'ibm',
               'vllm-project', 'ray-project', 'mlflow', 'bentoml', 'triton-inference-server',
               'gradio-app', 'streamlit', 'intel', 'kubeflow', 'feast-dev', 'mosaicml',
               'bigscience', 'eleutherai', 'facebookresearch', 'pytorch', 'tensorflow',
               'onnx', 'ml-explore', 'unslothai', 'vllm', 'mlc-ai', 'ollama', 'lm-studio',
               'guardrails-ai', 'llamaindex', 'pydantic', 'langgraph', 'crewaiinc',
               'transformerlab', 'giskard-ai', 'promptfoo', 'haystackai',
               'comfyanonymous', 'automatic1111', 'invoke-ai', 'lllyasviel',
               'scikit-learn', 'pandas-dev', 'numpy', 'scipy', 'jupyter',
               'open-mmlab', 'ultralytics', 'paddlepaddle', 'pjlab-adg',
               'allenai', 'salesforceresearch', 'stability-ai', 'runwayml',
               'vercel', 'nextauthjs'}
    if r.split('/')[0] in ai_orgs: return 'huntr-ai-heuristic', 'https://huntr.com/'
    return None, None

eligible = []
for h in fresh:
    program, url = why_eligible(h['repo'])
    if program:
        h['bounty_program'] = program; h['bounty_url'] = url
        eligible.append(h)
log('filter', 'ok', f'eligible={len(eligible)}')

# ===== analyze top targets until verified or out of time =====
eligible.sort(key=lambda h: h['score'], reverse=True)
verified_count = 0
analyzed_count = 0

SYSTEM_PROMPT = """You are a security researcher analyzing open-source code for validation bypasses.

You know these bug classes cold:
- URL parser vs validator differential (urlparse vs requests, new URL vs fetch, url.Parse vs net/http). Payloads: userinfo (http://evil.com#@internal/), backslash (http://evil.com\\@internal/), IPv6 zone id, decimal/hex IP.
- Unanchored regex (re.search vs re.fullmatch, Regex.IsMatch without ^$)
- Suffix match without dot prefix (.endswith('.evil.com') accepting 'attacker-evil.com')
- Case/Unicode normalization gap (ToLower but no NFKC, Turkish I, fullwidth chars)
- Path join before normalize (path.join then readFile without resolving up-levels)
- Deserialization gates (pickle, unserialize, yaml.Loader, readObject with user input)
- Prompt-injection filter that uses substring/regex without handling homoglyphs, base64, tool-chained injections

Respond as STRICT JSON with exactly these fields:
{
  "exploitable": true|false,
  "class": "one-word",
  "validator_line": "exact line from source, or null",
  "payload": "concrete payload string, or null",
  "verification_python": "self-contained python3 stdlib-only snippet that prints the string 'VB_BYPASS_VERIFIED' to stdout IFF the payload demonstrates the bypass. Must not make network calls. Should implement the VALIDATOR ONLY (mimic it exactly) and show the mismatch. Or null.",
  "expected_marker": "VB_BYPASS_VERIFIED",
  "impact": "RCE|SSRF-to-metadata|auth-bypass|path-traversal|prompt-injection|deserialization-rce|other",
  "confidence": "high|medium|low",
  "reasoning": "2-4 sentence technical explanation"
}

Rules: If you cannot find a concrete bypass, set exploitable=false and set payload/verification_python/validator_line to null. NEVER invent a payload you cannot verify. The verification snippet must ACTUALLY demonstrate the bypass when run."""

for target in eligible[:MAX_ANALYZE]:
    if over_budget(): break
    analyzed_count += 1
    # fetch source
    raw_url = f'https://raw.githubusercontent.com/{target["repo"]}/{target["sha"]}/{target["path"]}'
    code, body = http('GET', raw_url, headers=GH_HDR)
    if code != 200:
        log('fetch', 'fail', f'{target["repo"]}:{target["path"]} code={code}')
        continue
    src = body.decode('utf-8', errors='replace')
    if len(src) > 40000: src = src[:40000]  # truncate giant files
    # call gemma
    prompt_user = f"File: {target['repo']}::{target['path']}\nBounty: {target['bounty_program']}\nPattern class: {target['class']}\n\n```\n{src}\n```\n\nFind the bypass."
    or_body = {
        'model': MODEL,
        'messages': [{'role': 'system', 'content': SYSTEM_PROMPT}, {'role': 'user', 'content': prompt_user}],
        'temperature': 0.2, 'max_tokens': 2000,
        'response_format': {'type': 'json_object'},
    }
    code, body = http('POST', 'https://openrouter.ai/api/v1/chat/completions', headers=OR_HDR, body=or_body, timeout=180)
    if code != 200:
        log('llm', 'fail', f'code={code} body={body[:200]!r}')
        continue
    try:
        resp = json.loads(body)
        content = resp['choices'][0]['message']['content']
        # strip code fences if present
        content = re.sub(r'^```(?:json)?\s*|\s*```$', '', content.strip(), flags=re.MULTILINE)
        analysis = json.loads(content)
    except Exception as e:
        log('llm-parse', 'fail', f'{target["repo"]} err={e}')
        continue

    cur.execute("INSERT INTO validation_breaker.repos_scanned(repo,path,iter,flagged) VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                (target['repo'], target['path'], iter_n, bool(analysis.get('exploitable'))))

    if not analysis.get('exploitable') or not analysis.get('verification_python'):
        cur.execute("INSERT INTO validation_breaker.misses(iter,repo,file_path,attack_class,confidence,reason) VALUES(%s,%s,%s,%s,%s,%s)",
                    (iter_n, target['repo'], target['path'], analysis.get('class'), analysis.get('confidence'), (analysis.get('reasoning') or '')[:2000]))
        log('miss', 'ok', f'{target["repo"]} {analysis.get("class")} {analysis.get("confidence")}')
        continue

    # verify
    marker = analysis.get('expected_marker') or 'VB_BYPASS_VERIFIED'
    with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False) as f:
        f.write(analysis['verification_python']); script = f.name
    try:
        r = subprocess.run(['python3', script], capture_output=True, text=True, timeout=30)
        out = (r.stdout or '') + '\n--STDERR--\n' + (r.stderr or '')
        verified = marker in r.stdout
    except Exception as e:
        out = f'exec error: {e}'; verified = False
    finally:
        try: os.unlink(script)
        except: pass

    if verified:
        verified_count += 1
        cur.execute("""INSERT INTO validation_breaker.findings
            (iter,repo,file_path,validator_line,attack_class,payload,verification_output,impact,bounty_program,bounty_url,confidence,reasoning)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (iter_n, target['repo'], target['path'], analysis.get('validator_line'), analysis.get('class'),
             analysis.get('payload'), out[:8000], analysis.get('impact'), target['bounty_program'], target['bounty_url'],
             analysis.get('confidence'), analysis.get('reasoning')))
        log('FINDING', 'verified', f'{target["repo"]}:{target["path"]} {analysis.get("class")} {analysis.get("impact")}')
    else:
        cur.execute("INSERT INTO validation_breaker.misses(iter,repo,file_path,attack_class,confidence,reason) VALUES(%s,%s,%s,%s,%s,%s)",
                    (iter_n, target['repo'], target['path'], analysis.get('class'), analysis.get('confidence'),
                     f"verification failed. {(analysis.get('reasoning') or '')[:1500]}"))
        log('unverified', 'ok', f'{target["repo"]} {analysis.get("class")}')

# ===== summary =====
log('done', 'ok', f'iter={iter_n} hits={len(all_hits)} fresh={len(fresh)} eligible={len(eligible)} analyzed={analyzed_count} verified={verified_count}')

# persist progress log to repo file
with open('progress.log', 'a') as f:
    f.write('\n'.join(PROG) + '\n\n')
with open('LATEST.md', 'w') as f:
    f.write(f"# Iter {iter_n}\n\n- Hits: {len(all_hits)}\n- Fresh: {len(fresh)}\n- Eligible: {len(eligible)}\n- Analyzed: {analyzed_count}\n- Verified: {verified_count}\n\nSee Neon: `SELECT * FROM validation_breaker.findings ORDER BY id DESC;`\n")

cur.close(); conn.close()
print(f"\n=== iter {iter_n}: {len(all_hits)} hits, {len(eligible)} eligible, {analyzed_count} analyzed, {verified_count} verified ===")
