# z3rgRush

**Tor-powered web fuzzer** with rotating headers and multiple circuits for anonymous directory bruteforcing.

## Quick Start

```bash
./z3rgRush.py -t "http://example.com/{SWARM}" -w wordlist.txt
```

## Usage

```bash
z3rgRush.py -t TARGET -w WORDLIST [-c CIRCUITS] [--workers N] [-f EXTS] [-v]
```

| Flag | Purpose | Default |
|------|---------|---------|
| `-t` | URL w/ `{SWARM}` | req |
| `-w` | Wordlist | req |
| `-c` | Tor circuits | 3 |
| `--workers` | Threads | =circuits |
| `-f` | Extensions file | - |
| `--post-data` | POST fuzzing | GET URL |
| `-rc` | Success codes | 200 |

## Examples

```bash
# Basic dir fuzzing
./z3rgRush.py -t "http://site/{SWARM}" -w dirs.txt

# Files + extensions
./z3rgRush.py -t "https://target/{SWARM}" -w files.txt -f exts.txt -c 5

# POST payloads
./z3rgRush.py -t "http://api/" -w payloads.txt --post-data -m POST
```

**Output:** Circuit/IP/status/size/URL for hits (200,403,etc).

**Author:** derErntehelfer
