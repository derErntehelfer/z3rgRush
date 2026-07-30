# z3rgRush

Tor-powered web fuzzer for anonymous directory and parameter bruteforcing. Features rotating request headers, multiple isolated Tor circuits, intelligent circuit health-checks to prevent global slowdowns, retry handling, optional upstream exit proxies, and recursive follow-up fuzzing.

## Quick Start

```bash
./z3rgRush.py -t "http://example.com/{SWARM}" -w wordlist.txt
```

## Usage

```bash
z3rgRush.py -t TARGET -w WORDLIST [-c CIRCUITS] [--workers N] [-m METHOD] [-f EXTS] [--timeout SECONDS] [-v]
             [--post-data] [--headers HEADERS] [-rc CODES] [-ep] [-r DEPTH]
```

| Flag | Purpose | Default |
| --- | --- | --- |
| `-t`, `--target` | Target URL using `{SWARM}` as the fuzz placeholder | *required* |
| `-w`, `--wordlist` | Wordlist file containing payloads | *required* |
| `-c`, `--circuits` | Number of Tor circuits to create | `3` |
| `--workers` | Number of concurrent worker threads | `10 per circuit` (min 16) |
| `-m`, `--method` | HTTP method (`GET`, `POST`, `HEAD`, `OPTIONS`, `PUT`, `DELETE`) | `GET` |
| `-f`, `--filetype` | Single extension or extension list file to append to payloads | *none* |
| `--timeout` | HTTP request timeout in seconds | `10.0` |
| `-v`, `--verbose` | Enable detailed bootstrap and request logging | *off* |
| `--post-data` | Send wordlist entries as POST data instead of URL fuzzing | *off* |
| `--headers` | Use `headers.json` or provide custom `Key:Value` headers | default headers file if present |
| `-rc`, `--return-codes` | HTTP status codes treated as hits | `200` |
| `-ep`, `--use-exit-proxy` | Route traffic through additional upstream exit proxies | *off* |
| `-r`, `--recursion` | Recursion depth for re-fuzzing discovered hits | `0` |

## Examples

```bash
# Basic directory fuzzing
./z3rgRush.py -t "http://site/{SWARM}" -w dirs.txt

# Files plus extensions with 5 circuits
./z3rgRush.py -t "https://target/{SWARM}" -w files.txt -f exts.txt -c 5

# POST fuzzing
./z3rgRush.py -t "http://api/" -w payloads.txt --post-data

# Custom HTTP Method (e.g., PUT or OPTIONS)
./z3rgRush.py -t "http://api/{SWARM}" -w paths.txt -m PUT

# Custom headers from JSON
./z3rgRush.py -t "https://target/{SWARM}" -w wordlist.txt --headers headers.json

# Custom inline headers
./z3rgRush.py -t "https://target/{SWARM}" -w wordlist.txt --headers "User-Agent:TestAgent" "X-Test:1"

# Recursive fuzzing
./z3rgRush.py -t "https://target/{SWARM}" -w wordlist.txt -r 1

# Use upstream exit proxies
./z3rgRush.py -t "https://target/{SWARM}" -w wordlist.txt -ep
```

## Features

* **Intelligent Circuit Routing**: Implements health checks and cooldowns to automatically bypass circuits that are currently rotating or recovering from timeouts, preventing global thread starvation.
* **High Concurrency**: Worker threads scale dynamically (defaulting to 10 per circuit) to ensure timeouts on one circuit don't halt the entire fuzzing process.
* Builds multiple isolated Tor circuits automatically in parallel.
* Rotates request headers across a configurable header pool.
* Uses `headersForRotation.json` automatically when present, with fallback defaults when absent.
* Supports multiple HTTP methods (GET, POST, HEAD, OPTIONS, PUT, DELETE).
* Accepts single extensions or extension lists for file discovery.
* Retries failed payloads and blacklists bad upstream proxies when exit-proxy mode is enabled.
* Supports recursive fuzzing from successful hits.

## Output

Each hit is reported with circuit index, exit IP, HTTP status, response size, and final URL.  
Verbose mode (`-v`) also prints the active header set and routing chain.

## Notes

* `{SWARM}` is replaced with each payload in the target URL.
* When `--post-data` is enabled, payloads are sent as POST bodies instead of substituted into the URL.
* If `--circuits` is not paired with `--workers`, the worker count defaults to **10 workers per circuit** (minimum 16) to maintain high throughput and resilience during network hiccups.
* The tool limits circuits to a maximum of 16.
* Exit-proxy mode (`-ep`) is experimental; requests may occasionally come out malformed after the proxy chain. Retry logic attempts to collect and resend these, but kinks are still being worked out.

## Author

derErntehelfer

## Acknowledgment

This tool was developed with the help of genAI, while still being understood, tested, and controlled by the author.
