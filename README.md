# Web Proxy Autograder

## What this script does
Grades a student HTTP proxy for:
```
1) correct forwarding,
2) blocklist enforcement,
3) caching behavior (serve-from-cache + TTL refresh), and
4) extra credit link prefetch.
```
Prereqs
```
Linux with iptables (root required)
make, a working ./proxy target (built by make)
Python 3.8+ with psutil (sudo apt install python3-psutil)
Internet access to http://netsys.cs.colorado.edu/
```
## How to run
```
sudo python3 grade.py \
  --port 8000 \
  --timeout 20 \
  --cache-dir cache \
  --artifacts-dir artifacts
```
Arguments
```
--port: proxy listen port (default 8000)
--timeout: cache TTL passed to ./proxy (default 20 seconds)
--cache-dir: proxy cache directory (default ./cache)
--artifacts-dir: where all outputs go (default ./artifacts)
--blocklist: filename read by the proxy (default blocklist in CWD)
```
Important: Script must run as root (uses iptables to block the origin during some tests).

All artifacts are saved under --artifacts-dir (default: ./artifacts/).  
```
proxy.log – stdout/stderr of the proxy while grading
ref_index.html – direct fetch of the reference page
proxy_index.html – first fetch via proxy
proxy_index_cached.html – fetch via proxy while origin blocked (Test 3a)
proxy_index_after_ttl.html – fetch via proxy after TTL (Test 3b)
ref_text1.txt, ref_apple_ex.png – reference files for prefetch (Test 4)
proxy_text1_blocked.txt, proxy_apple_ex_blocked.png – proxy responses while origin blocked (Test 4)
```

## Step-by-step flow
Before running tests:
```
Clear cache: empties --cache-dir.
Write blocklist: creates ./blocklist with sample entries.
Build: runs make clean && make (warnings suppressed).
Free port: kills any process bound to --port.
Start proxy: runs ./proxy <port> <timeout>, waits for it to listen.
Run tests (1→4).
```

Test 1 — Forwarding & Relaying (60 pts)
- Action: directly fetch `http://netsys.cs.colorado.edu/index.html` → `ref_index.html`
- Fetch the same URL via the proxy → `proxy_index.html`
- Pass: byte-for-byte equal and non-empty.
- Score: `60/60` if equal, else `0`.

Test 2 — Blocklist (10 pts)
- Action: send raw `HTTP GET` through the proxy to each host in `./blocklist`.
- Pass: proxy returns `HTTP 403` for all entries.
- Score: `10/10` if all blocked, else `0`.

Test 3a — Serve from Cache with Origin Blocked (20 pts)
- Goal: verify proxy serves index.html from cache when origin is unreachable.
- Action: after the first proxy fetch (Test 1), locate the cached file in --cache-dir using a relaxed content match (tolerates extra metadata/headers). The script prints the matched cache path.
- Record its mtime.
- Block origin (iptables REJECT to TCP:80).
- Fetch `index.html` via proxy again → `proxy_index_cached.html`.
- Pass:
  - Response is `200` and body equals the reference (not just “some” content).
  - Same cache file’s mtime did not change (true cache HIT).
- Score: `20/20` if both conditions hold, else `0`.

Test 3b — TTL Expire → Refresh & Cache Timestamp Update (10 pts)
- Goal: after TTL, the proxy should re-fetch and refresh cache.
- Action: locate the same cached file (relaxed match) and record its mtime.
- Wait TTL + 1 seconds.
- Fetch `index.html` via proxy → `proxy_index_after_ttl.html`.
- Pass:
  - Response is `200` and body equals the reference.
  - The same cache file’s mtime increased (cache refreshed).
- Score: `10/10` if both conditions hold, else `0`.

Test 4 — Link Prefetch (Extra +10 pts)
- Goal: validate that linked assets were prefetched and thus available offline.
- Action: directly fetch (no proxy) and save as references:
  - `http://netsys.cs.colorado.edu/files/text1.txt` → `ref_text1.txt`
  - `http://netsys.cs.colorado.edu/images/apple_ex.png` → `ref_apple_ex.png`
- Block origin (iptables).
- Request both files via the proxy while blocked:
- Save to `proxy_text1_blocked.txt`, `proxy_apple_ex_blocked.png`.
- Pass (per file): `200` and body equals its reference.
- Score: `+5` for each file served from cache (max `+10`).

## Notes & Tips
The script must run as `root`; it exits early with a clear message if not.

Origin blocking requires `iptables`; if unavailable, affected tests fail by design.

Cache file detection is relaxed (tolerates students storing `headers/metadata`).

The proxy is expected to read `blocklist` from the current working directory (file name configurable with `--blocklist`).

If make or `./proxy` is missing, the run stops and points to `artifacts/proxy.log` for build/run details.

## Test via commandline
```
# 1. Normal request
curl http://netsys.cs.colorado.edu

# 2. Request through local proxy on port 9000
curl -x http://127.0.0.1:9000 http://netsys.cs.colorado.edu

# 3. Resolve Hostname to IP
host netsys.cs.colorado.edu

# 4. Block direct access
sudo iptables -A OUTPUT -p tcp -d 198.59.7.17 --dport 80 -j DROP

# 5. Request through local proxy on port 9000
curl -x http://127.0.0.1:9000 http://netsys.cs.colorado.edu

# 6. Unblock
sudo iptables -D OUTPUT -p tcp -d 198.59.7.17 --dport 80 -j DROP
```


