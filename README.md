# z3rgRush

**Tor-powered web fuzzer** for anonymous directory and parameter bruteforcing, with rotating request headers, multiple Tor circuits, retry handling, optional upstream exit proxies, and recursive follow-up fuzzing.

## Quick Start

```bash
./z3rgRush.py -t "http://example.com/{SWARM}" -w wordlist.txt
```

## Usage

```bash
z3rgRush.py -t TARGET -w WORDLIST [-c CIRCUITS] [--workers N] [-f EXTS] [--timeout SECONDS] [-v]
             [--post-data] [--headers HEADERS] [-rc CODES] [-ep] [-r DEPTH]
```

| Flag | Purpose | Default |
|------|---------|---------|
| `-t`, `--target` | Target URL using `{SWARM}` as the fuzz placeholder | required |
| `-w`, `--wordlist` | Wordlist file containing payloads | required |
| `-c`, `--circuits` | Number of Tor circuits to create | `3` |
| `--workers` | Number of concurrent worker threads | same as circuits |
| `-f`, `--filetype` | Single extension or extension list file to append to payloads | none |
| `--timeout` | HTTP request timeout in seconds | `10.0` |
| `-v`, `--verbose` | Enable detailed bootstrap and request logging | off |
| `--post-data` | Send wordlist entries as POST data instead of URL fuzzing | off |
| `--headers` | Use `headers.json` or provide custom `Key:Value` headers | default headers file if present |
| `-rc`, `--return-codes` | HTTP status codes treated as hits | `200` |
| `-ep`, `--use-exit-proxy` | Route traffic through additional upstream exit proxies | off |
| `-r`, `--recursion` | Recursion depth for re-fuzzing discovered hits | `0` |

## Examples

```bash
# Basic directory fuzzing
./z3rgRush.py -t "http://site/{SWARM}" -w dirs.txt

# Files plus extensions
./z3rgRush.py -t "https://target/{SWARM}" -w files.txt -f exts.txt -c 5

# POST fuzzing
./z3rgRush.py -t "http://api/" -w payloads.txt --post-data -m POST

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

- Builds multiple Tor circuits automatically.
- Rotates request headers across a configurable header pool.
- Uses `headers.json` automatically when present, with fallback defaults when absent.
- Supports GET fuzzing and POST payload fuzzing.
- Accepts single extensions or extension lists for file discovery.
- Retries failed payloads and blacklists bad upstream proxies when exit-proxy mode is enabled.
- Supports recursive fuzzing from successful hits.

## Output

Each hit is reported with circuit index, exit IP, HTTP status, response size, and final URL.  
Verbose mode also prints the active header set and routing chain.

## Notes

- `{SWARM}` is replaced with each payload in the target URL.
- When `--post-data` is enabled, payloads are sent as POST bodies instead of substituted into the URL.
- If `--circuits` is not paired with `--workers`, worker count defaults to the circuit count.
- The tool limits circuits to a maximum of 16.
- Exit-proxy mode is experimental.

## Author

derErntehelfer

## Acknowledgment

This tool was developed with the help of genAI, while still being understood, tested, and controlled by the author.
