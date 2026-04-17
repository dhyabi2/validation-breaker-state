#!/usr/bin/env python3
"""Validation-breaker one iteration. Run in GitHub Actions. Commits handled by the workflow."""
import base64, json, os, random, sys, time, urllib.parse, urllib.request

TOKEN = os.environ['GH_PAT']
REPO_OWNER = 'dhyabi2'
REPO_NAME = 'validation-breaker-state'

HDRS = {
    'Authorization': f'Bearer {TOKEN}',
    'Accept': 'application/vnd.github.v3+json',
    'User-Agent': 'vb-bot',
}

def http(method, url, body=None):
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method, headers=HDRS)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return 0, repr(e).encode()

def read_local(path, default=''):
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return default

def write_local(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None
    with open(path, 'w') as f:
        f.write(content)

def append_local(path, content):
    with open(path, 'a') as f:
        f.write(content)

# ============ state ============
iter_n = int(read_local('iter_count.txt', '0').strip() or '0') + 1
write_local('iter_count.txt', f'{iter_n}\n')
print(f'iter_n={iter_n}')

tried_patterns = set()
for line in read_local('patterns_tried.tsv').splitlines()[1:]:  # skip header
    parts = line.split('\t')
    if len(parts) >= 4:
        tried_patterns.add((parts[1], parts[2], parts[3]))

# ============ master patterns ============
MASTER = [
    ('python','ssrf-suffix','"urlparse" "hostname" ".endswith(" language:Python'),
    ('python','ssrf-parser','"urlparse" "netloc" "requests.get" language:Python'),
    ('python','path-traversal','"os.path.join" "request." "open(" language:Python'),
    ('python','unanchored-regex','"re.search" "host" "requests" language:Python'),
    ('python','prompt-injection','"re.search" "ignore previous" language:Python'),
    ('python','unicode-gap','".lower()" "not in" "blocked" language:Python'),
    ('js','path-traversal','"path.join" "req.query" "sendFile" language:JavaScript'),
    ('js','ssrf-url-parser','"new URL" ".hostname ===" language:JavaScript'),
    ('js','prompt-injection','".match" "jailbreak" language:JavaScript'),
    ('js','unanchored-regex','"new RegExp" ".test(" "allowed" language:JavaScript'),
    ('js','unicode-gap','".toLowerCase()" "includes" "host" language:JavaScript'),
    ('js','deserialization','"JSON.parse" "req.body" "eval" language:JavaScript'),
    ('ts','path-traversal','"path.resolve" "req.params" "readFile" language:TypeScript'),
    ('ts','ssrf-url-parser','"new URL" "hostname" "fetch" language:TypeScript'),
    ('ts','prompt-injection','"includes" "ignore" "instructions" language:TypeScript'),
    ('ts','unanchored-regex','"RegExp" "test" "hostname" language:TypeScript'),
    ('ts','unicode-gap','"normalize" "NFC" "compare" language:TypeScript'),
    ('ts','deserialization','"class-transformer" "plainToInstance" language:TypeScript'),
    ('go','ssrf-parser','"url.Parse" ".Host" "http.Get" language:Go'),
    ('go','path-traversal','"filepath.Join" "r.URL.Query" language:Go'),
    ('go','unanchored-regex','"regexp.MatchString" "host" language:Go'),
    ('go','deserialization','"json.Unmarshal" "r.Body" language:Go'),
    ('go','unicode-gap','"strings.ToLower" "==" "allowed" language:Go'),
    ('go','prompt-injection','"strings.Contains" "prompt" "ignore" language:Go'),
    ('rust','unanchored-regex','"Regex::new" "is_match" "reqwest" language:Rust'),
    ('rust','ssrf-url-parser','"Url::parse" ".host_str" language:Rust'),
    ('rust','path-traversal','"Path::new" "query" "read_to_string" language:Rust'),
    ('rust','deserialization','"serde_json::from_str" "body" language:Rust'),
    ('rust','unicode-gap','".to_lowercase" "==" language:Rust'),
    ('rust','prompt-injection','".contains" "system" "prompt" language:Rust'),
    ('java','deserialization','"ObjectInputStream" "readObject" language:Java'),
    ('java','ssrf-url-parser','"new URL" ".getHost()" language:Java'),
    ('java','path-traversal','"Paths.get" "getParameter" language:Java'),
    ('java','unanchored-regex','"Pattern.compile" ".matcher" "find()" language:Java'),
    ('java','unicode-gap','".toLowerCase()" "equals" "allowed" language:Java'),
    ('java','prompt-injection','".contains" "jailbreak" language:Java'),
    ('ruby','ssrf-url-parser','"URI.parse" ".host" "Net::HTTP" language:Ruby'),
    ('ruby','path-traversal','"File.join" "params" "File.read" language:Ruby'),
    ('ruby','unanchored-regex','"=~" "host" "http.get" language:Ruby'),
    ('ruby','deserialization','"Marshal.load" "params" language:Ruby'),
    ('ruby','unicode-gap','".downcase" "==" language:Ruby'),
    ('ruby','prompt-injection','".match" "ignore" "prompt" language:Ruby'),
    ('php','ssrf-parser','"parse_url" "host" "file_get_contents" language:PHP'),
    ('php','path-traversal','"file_get_contents" "$_GET" language:PHP'),
    ('php','unanchored-regex','"preg_match" "host" language:PHP'),
    ('php','deserialization','"unserialize" "$_POST" language:PHP'),
    ('php','unicode-gap','"strtolower" "==" "allowed" language:PHP'),
    ('php','prompt-injection','"strpos" "ignore previous" language:PHP'),
    ('csharp','ssrf-url-parser','"new Uri" ".Host" "HttpClient" language:C#'),
    ('csharp','path-traversal','"Path.Combine" "Request." language:C#'),
    ('csharp','unanchored-regex','"Regex.IsMatch" "host" language:C#'),
    ('csharp','deserialization','"BinaryFormatter" "Deserialize" language:C#'),
    ('csharp','unicode-gap','".ToLower()" "==" "Allowed" language:C#'),
    ('csharp','prompt-injection','".Contains" "prompt" "ignore" language:C#'),
    ('kotlin','path-traversal','"File(" "request." "readText" language:Kotlin'),
    ('kotlin','ssrf-url-parser','"URL(" ".host" language:Kotlin'),
    ('kotlin','unanchored-regex','"Regex(" ".containsMatchIn" language:Kotlin'),
    ('kotlin','deserialization','"ObjectMapper" "readValue" language:Kotlin'),
    ('kotlin','unicode-gap','".lowercase()" "==" language:Kotlin'),
    ('kotlin','prompt-injection','".contains" "system" language:Kotlin'),
]

unused = [p for p in MASTER if p not in tried_patterns]
random.seed(int(time.time()))
picked = random.sample(unused, min(10, len(unused))) if unused else []
print(f'patterns_tried={len(tried_patterns)}, unused={len(unused)}, picked={len(picked)}')

# ============ append patterns to tsv ============
if not os.path.exists('patterns_tried.tsv') or not read_local('patterns_tried.tsv').strip():
    write_local('patterns_tried.tsv', 'iter\tlang\tclass\tquery\n')
with open('patterns_tried.tsv', 'a') as f:
    for (lang, cls, q) in picked:
        f.write(f'{iter_n}\t{lang}\t{cls}\t{q}\n')

# ============ search ============
all_hits = []
for (lang, cls, q) in picked:
    url = 'https://api.github.com/search/code?' + urllib.parse.urlencode({'q': q, 'per_page': 10})
    code, body = http('GET', url)
    if code == 200:
        d = json.loads(body)
        items = d.get('items', [])
        for i in items:
            all_hits.append({
                'iter': iter_n,
                'lang': lang, 'class': cls,
                'repo': i['repository']['full_name'],
                'path': i['path'],
                'sha': i['sha'],
                'score': i.get('score', 0),
            })
        print(f'  {lang}/{cls}: {d.get("total_count",0)} total, {len(items)} fetched')
    else:
        print(f'  {lang}/{cls}: HTTP {code}')
    time.sleep(3)

print(f'total hits: {len(all_hits)}')

# ============ dedup against repos_scanned ============
seen_repos = set()
for line in read_local('repos_scanned.jsonl').splitlines():
    try:
        seen_repos.add(json.loads(line).get('repo'))
    except: pass

fresh_hits = [h for h in all_hits if h['repo'] not in seen_repos]
print(f'fresh hits (not scanned before): {len(fresh_hits)}')

# ============ record per-iter artefacts ============
iter_dir = f'iters/{iter_n:04d}'
os.makedirs(iter_dir, exist_ok=True)
with open(f'{iter_dir}/patterns.tsv', 'w') as f:
    f.write('lang\tclass\tquery\n')
    for (l,c,q) in picked:
        f.write(f'{l}\t{c}\t{q}\n')
with open(f'{iter_dir}/hits.jsonl', 'w') as f:
    for h in all_hits:
        f.write(json.dumps(h)+'\n')

# ============ pick ONE target and analyze ============
if fresh_hits:
    target = max(fresh_hits, key=lambda h: h.get('score', 0))
    raw_url = f'https://raw.githubusercontent.com/{target["repo"]}/{target["sha"]}/{target["path"]}'
    code, body = http('GET', raw_url)
    src = body.decode('utf-8', errors='replace') if code == 200 else ''
    if src:
        flags = []
        if 're.search(' in src and 're.fullmatch(' not in src: flags.append('unanchored-re-search')
        if '.endswith(' in src and 'startswith' not in src: flags.append('suffix-match')
        if '.lower()' in src or '.toLowerCase(' in src: flags.append('case-normalize')
        if 'urlparse' in src and '.hostname' in src: flags.append('urlparse-hostname')
        if 'new URL' in src and '.hostname' in src: flags.append('url-hostname-js')

        with open(f'{iter_dir}/target.md', 'w') as f:
            f.write(f'# {target["repo"]} :: {target["path"]}\n\n')
            f.write(f'Score: {target["score"]}  Lang/Class: {target["lang"]}/{target["class"]}\n\n')
            f.write(f'Heuristic flags: {flags}\n\n')
            f.write('```\n' + src[:4000] + '\n```\n')

        # record miss (no actual verification done in this pass)
        with open('misses.jsonl', 'a') as f:
            f.write(json.dumps({
                'iter': iter_n, 'repo': target['repo'], 'path': target['path'],
                'flags': flags, 'reason': 'heuristic only, no verified PoC yet'
            }) + '\n')
        print(f'analyzed {target["repo"]}:{target["path"]} flags={flags}')
    else:
        print(f'could not fetch raw source for {target["repo"]}')

    # record all seen repos
    with open('repos_scanned.jsonl', 'a') as f:
        for h in fresh_hits:
            f.write(json.dumps({'iter': iter_n, 'repo': h['repo'], 'path': h['path']}) + '\n')

# ============ summary ============
summary = f'iter {iter_n}: {len(picked)} patterns, {len(all_hits)} hits, {len(fresh_hits)} fresh, 0 verified bypasses\n'
with open('LATEST.md', 'w') as f:
    f.write(f'# Latest iteration\n\n{summary}\n\nSee [iters/](iters/) for per-iter artefacts.\n')
print(summary)
