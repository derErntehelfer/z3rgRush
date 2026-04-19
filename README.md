# z3rgRush - Tor-Powered Web Fuzzer

Creates isolated Tor circuits for anonymous web directory fuzzing.

## Features
- 1-16 independent Tor instances
- Auto circuit rotation (NEWNYM)
- Concurrent requests with workers
- File extension wordlist support

## Installation
```bash
sudo dpkg -i z3rgrush_*.deb
# or
pip install .
```

**Requires:** `tor`, `python3-stem`, `python3-requests`

## Usage
```bash
z3rgRush -t "http://example.com/{SWARM}" -w wordlist.txt

# With 5 circuits + PHP fuzzing
z3rgRush -t "https://target.tld/admin/{SWARM}" -w common.txt -f php.txt -c 5
```

**Key args:**
- `-t/--target`: URL with `{SWARM}` placeholder (required)
- `-w/--wordlist`: Wordlist path (required)
- `-c/--circuits`: 1-16 Tor circuits (default: 3)
- `-f/--filetype`: Extensions file or single `.php`
- `--workers`: Concurrent threads

## Example Outputz3rgRush - Tor-Powered Web Fuzzer

z3rgRush creates multiple isolated Tor circuits to anonymously fuzz web directories and files. Perfect for red team reconnaissance without IP exposure.
Features

    Multiple independent Tor instances (1-16 circuits)

    Automatic circuit rotation with NEWNYM signals

    Concurrent request handling with configurable workers

    File extension fuzzing from wordlists

    Automatic cleanup of Tor processes/data directories

Installation

bash
# From deb package
sudo dpkg -i z3rgrush_*.deb

# Or from source
pip install .

Dependencies: python3-stem, python3-requests, tor
Usage

text
z3rgRush -t "http://example.com/{SWARM}" -w /path/to/wordlist.txt [-c 5] [-f extensions.txt]

z3rg -t "https://target.com/images/{SWARM}" -w /usr/share/wordlists/dirb/common.txt -c 8 --workers 4

Arguments:

    -t, --target Target URL with {SWARM} fuzz point (required)

    -w, --wordlist Path to wordlist file (required)

    -c, --circuits Number of Tor circuits (1-16, default: 3)

    --workers Concurrent threads (default: circuits count)

    -f, --filetype Single extension (.php) or file with extensions

    --timeout Request timeout in seconds (default: 10)

    -v, --verbose Show Tor bootstrap logs

Example

bash
# Basic directory fuzzing
z3rgRush -t "http://example.com/files/{SWARM}" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# PHP file fuzzing with 5 circuits
z3rgRush -t "https://target.tld/admin/{SWARM}" -w common.txt -f php.txt -c 5

Output Example

text
Circuit 0 (port 9051): IP=185.220.101.XX, status=200, len=1234 -> URL: http://example.com/files/admin.php
Circuit 2 (port 9055): IP=156.236.76.XX, error -> HTTPSConnectionPool (URL: http://example.com/files/config.bak)
Payload http://example.com/files/config.bak returned to Work Container

Workflow

    Launches N isolated Tor processes with unique SOCKS/Control ports

    Generates payloads by replacing {SWARM} with wordlist entries (+ extensions)

    Distributes requests across circuits with automatic IP rotation

    Retries failed payloads through available circuits

    Graceful cleanup on Ctrl+C or completion

Requirements

    Linux with Tor binary accessible

    Python 3.8+

    stem and requests libraries

    Write access for temp directories

Troubleshooting

    Tor bootstrap hangs: Check tor binary path, increase timeout

    Permission errors: Run with sufficient privileges for port binding

    No circuits created: Verify stem version ≥1.8.0
