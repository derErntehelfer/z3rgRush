# z3rgRush

z3rgRush is a Tor-powered web fuzzer for anonymous directory, file, parameter, and body bruteforcing over HTTP/HTTPS.

It creates multiple isolated Tor circuits, rotates request headers, applies circuit cooldowns and rotation logic, retries failed payloads, supports recursive fuzzing, and includes experimental upstream exit-proxy support.

## quickStart

```bash
./z3rgRush.py -t "http://example.com/{SWARM}" -w wordlist.txt
```

## usage

```text
z3rgRush.py -t TARGET -w WORDLIST [-c CIRCUITS] [--workers N] [-m METHOD]
            [-f EXTS] [-d BODY] [--timeout SECONDS] [-v] [--post-data]
            [--headers [HEADERS ...]] [-rc CODES ...] [-ep] [-r DEPTH]
```

## flags

| flag | purpose | default |
|---|---|---|
| `-t`, `--target` | Target URL. `{SWARM}` marks the injection point. HTTP/HTTPS only. | required |
| `-w`, `--wordlist` | Wordlist file containing payloads. | required |
| `-c`, `--circuits` | Number of Tor circuits to create. Maximum is 16. | `3` |
| `--workers` | Number of concurrent worker threads. If unset, defaults to `max(16, circuits * 10)`. Forced to `1` when `-ep/--use-exit-proxy` is enabled. | auto |
| `-m`, `--method` | HTTP method: `GET`, `POST`, `HEAD`, `OPTIONS`, `PUT`, `DELETE`, `PATCH`. When `--post-data` or `-d/--body` is used, requests default to `POST`. | `GET` |
| `-f`, `--filetype` | Single extension or file containing extensions. Extensions are appended to each payload. | none |
| `-d`, `--body` | Request body template. Use `{SWARM}` as the injection point. JSON bodies are detected automatically. | none |
| `--timeout` | HTTP request timeout in seconds. | `10.0` |
| `-v`, `--verbose` | Enable verbose logging, including header sets and request chain details. | off |
| `--post-data` | Send wordlist entries as the request body instead of only using them in the URL. | off |
| `--headers` | Load a JSON header config file or provide inline `Key:Value` headers. If omitted, z3rgRush tries `headersForRotation.json`. | `headersForRotation.json` if present |
| `-rc`, `--return-codes` | HTTP status codes treated as hits. Accepts multiple arguments or comma-separated values. | `200` |
| `-ep`, `--use-exit-proxy` | Route traffic through additional upstream exit proxies. Experimental. | off |
| `-r`, `--recursion` | Recursion depth for re-fuzzing discovered hits. | `0` |

## examples

### basic directory fuzzing

```bash
./z3rgRush.py -t "http://site/{SWARM}" -w dirs.txt
```

### file discovery with extensions and more circuits

```bash
./z3rgRush.py -t "https://target/{SWARM}" -w files.txt -f exts.txt -c 5
```

### POST body fuzzing with raw wordlist entries

```bash
./z3rgRush.py -t "http://api/login" -w payloads.txt --post-data
```

### JSON body template

```bash
./z3rgRush.py -t "http://api/json" -w payloads.txt -d '{"username":"{SWARM}"}'
```

### form body template

```bash
./z3rgRush.py -t "http://api/form" -w payloads.txt -d "param={SWARM}"
```

### custom HTTP method

```bash
./z3rgRush.py -t "http://api/{SWARM}" -w paths.txt -m PATCH
```

### custom return codes

```bash
./z3rgRush.py -t "https://target/{SWARM}" -w wordlist.txt -rc 200 301 302
```

or comma-separated:

```bash
./z3rgRush.py -t "https://target/{SWARM}" -w wordlist.txt -rc 200,301,302
```

### custom headers from JSON

```bash
./z3rgRush.py -t "https://target/{SWARM}" -w wordlist.txt --headers headers.json
```

### custom inline headers

```bash
./z3rgRush.py -t "https://target/{SWARM}" -w wordlist.txt --headers "User-Agent:TestAgent" "X-Test:1"
```

### recursive fuzzing

```bash
./z3rgRush.py -t "https://target/{SWARM}" -w wordlist.txt -r 1
```

### upstream exit proxies

```bash
./z3rgRush.py -t "https://target/{SWARM}" -w wordlist.txt -ep
```

## features

### isolated Tor circuits

z3rgRush builds multiple Tor circuits in parallel. Each circuit uses its own Tor process, SOCKS port, control port, and temporary data directory.

Circuit creation includes retry handling and bootstrap waiting. The maximum number of circuits is limited to 16.

### circuit routing and cooldowns

The fuzzer tracks circuit rotation state and avoids circuits that are currently cooling down after errors, timeouts, or rate-limit responses.

Responses that can trigger circuit rotation include, among others:

- `403`
- `429`
- `430`
- `440`
- `449`
- `502`
- `503`
- `504`
- `521`
- `523`
- `524`

Timeouts, connection errors, and request exceptions can also trigger rotation.

### retry handling

Failed payloads are returned to the work queue and retried. The current retry logic allows up to three retry passes before remaining failed payloads are reported.

### header rotation

z3rgRush rotates request headers using configurable header pools.

If no `--headers` argument is supplied, z3rgRush automatically tries to load:

```text
headersForRotation.json
```

If that file is not present, safe internal default header sets are used.

Inline headers provided through `--headers` are applied in addition to rotation defaults and override generated header values.

### HTTP method support

Supported methods:

- `GET`
- `POST`
- `HEAD`
- `OPTIONS`
- `PUT`
- `DELETE`
- `PATCH`

If `--post-data` or `-d/--body` is used, the request method defaults to `POST`. Explicit `GET` requests with body data are automatically converted to `POST`.

### body templating

The `-d/--body` option allows using `{SWARM}` inside the request body.

Example:

```bash
./z3rgRush.py -t "http://api/json" -w payloads.txt -d '{"user":"{SWARM}"}'
```

If the rendered body is valid JSON, z3rgRush sends it as JSON with:

```text
Content-Type: application/json
```

If it is not valid JSON, it is sent as form-encoded data with:

```text
Content-Type: application/x-www-form-urlencoded
```

When `--post-data` is used without a body template, the raw wordlist entry is sent as the request body with:

```text
Content-Type: text/plain
```

### extension handling

Use `-f/--filetype` to append extensions to payloads.

Single extension:

```bash
./z3rgRush.py -t "http://target/{SWARM}" -w files.txt -f php
```

Extension list:

```bash
./z3rgRush.py -t "http://target/{SWARM}" -w files.txt -f extensions.txt
```

If an extension begins with a dot, the dot is normalized. For example, both `php` and `.php` produce `payload.php`.

### recursive fuzzing

When recursion is enabled, successful hits based on `-rc/--return-codes` are used as new fuzz targets.

For each hit, z3rgRush:

1. removes query strings,
2. removes URL fragments,
3. removes trailing slashes,
4. appends `/{SWARM}`.

Example:

```text
https://target/admin
```

becomes:

```text
https://target/admin/{SWARM}
```

Recursive fuzzing is controlled with:

```bash
-r DEPTH
```

If no new hits are collected before the depth limit is reached, recursion stops early.

## headerRotation configuration

z3rgRush can load header rotation values from a JSON file.

Example `headersForRotation.json`:

```json
{
  "user_agents": [
    "Mozilla/5.0 (compatible; z3rgRush/1.0)"
  ],
  "accept_headers": [
    "*/*"
  ],
  "accept_languages": [
    "en-US,en;q=0.9"
  ],
  "accept_encodings": [
    "gzip, deflate"
  ],
  "referers": [
    "https://www.google.com/"
  ],
  "sec_fetch_dest": [
    "document"
  ],
  "sec_fetch_mode": [
    "navigate"
  ],
  "sec_fetch_site": [
    "same-origin"
  ],
  "sec_ch_ua_mobile": [
    "?0"
  ],
  "sec_ch_ua_platforms": [
    "\"Windows\""
  ]
}
```

Recognized keys include:

- `user_agents`
- `accept_headers`
- `accept_languages`
- `accept_encodings`
- `referers`
- `sec_fetch_dest`
- `sec_fetch_mode`
- `sec_fetch_site`
- `sec_ch_ua_mobile`
- `sec_ch_ua_platforms`

If a key is missing or empty, z3rgRush falls back to internal defaults for that key.

## exitProxyMode

Exit-proxy mode is enabled with:

```bash
-ep
```

or:

```bash
--use-exit-proxy
```

This mode attempts to chain Tor with additional upstream HTTP proxies.

Current behavior:

- requires `pyChainedProxy`,
- fetches public HTTP proxies from ProxyScrape,
- uses `curl` for proxy list retrieval,
- blacklists proxies that time out or fail,
- refetches proxies when all collected proxies are blacklisted,
- falls back to Tor-only when no usable upstream proxy is available,
- forces `--workers 1` because the current implementation uses experimental global socket patching.

This mode is experimental and may be unstable.

## requirements

### system requirements

- Tor binary available in `PATH`
- Python 3
- `curl` is required for exit-proxy proxy list retrieval

### python dependencies

Required:

```bash
python3 -m pip install "requests[socks]" stem rich
```

Optional:

```bash
python3 -m pip install argcomplete
```

Optional for exit-proxy mode:

```bash
python3 -m pip install pyChainedProxy
```

If `pyChainedProxy` is unavailable, exit-proxy mode is disabled.

## output

Each completed request is logged with:

- circuit index,
- HTTP method,
- Tor SOCKS port,
- exit IP or proxy chain info,
- HTTP status code,
- response length,
- final URL.

Successful hits, based on `-rc/--return-codes`, are collected and printed again at the end of the run.

Verbose mode adds more detail, including:

- active request headers,
- routing chain,
- Tor bootstrap and circuit details.

## notes

- `{SWARM}` is replaced with each generated payload.
- If `{SWARM}` appears in a URL fragment, z3rgRush warns because HTTP clients do not send URL fragments to the server.
- `{SWARM}` must appear in the target URL or body template unless `--post-data` is used.
- When `--post-data` is enabled, payloads are sent as request bodies.
- If `{SWARM}` is also present in the target URL while using `--post-data`, URL substitution still happens.
- If `--circuits` is used without `--workers`, z3rgRush automatically configures `max(16, circuits * 10)` workers.
- The maximum number of Tor circuits is 16.
- HTTP/HTTPS are currently the only supported URL schemes.

## currentLimitations

- only HTTP and HTTPS are supported,
- exit-proxy mode is experimental and forces one worker,
- recursion uses simple path-based target derivation,
- upstream exit-proxy lists depend on external public proxy sources,
- exit IP detection depends on external IP-check endpoints.

## roadmap

- add support for protocols besides HTTP/HTTPS,
- provide a proper `z3rg` alias,
- package at least for apt,
- fix bugs, inconveniences, and inconsistencies,

## author

derErntehelfer

## acknowledgment

This tool was developed with the help of genAI, while still being understood, tested, and controlled by the author.
