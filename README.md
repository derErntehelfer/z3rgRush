# z3rgRush - Tor-Powered Web Fuzzer

Creates isolated Tor circuits for anonymous web directory fuzzing.

## Features
- 1-16 independent Tor instances
- Auto circuit rotation (NEWNYM)
- Concurrent requests with workers
- File extension wordlist support

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

## Example Output
```bash
Circuit 0 (port 9051): IP=185.220.101.x, status=200 -> http://target/admin/config.php
Circuit 2 (port 9055): error -> http://target/admin/config.bak (retrying)
```

written and developed by derErntehelfer
