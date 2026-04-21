# z3rgRush

CLI tool that sends HTTP requests through multiple Tor circuits. Uses wordlists to fuzz URLs and rotates browser-like headers. Collects responses with specified status codes.[file:5]

## Files

- `z3rgRush.py` - Main CLI entry point[file:5]
- `torCircuitFactory.py` - Creates isolated Tor instances[file:4] 
- `circuitOvermind.py` - Manages requests across circuits with header rotation[file:3]
- `payloadFactory.py` - Generates fuzzing payloads from wordlists[file:2]
- `headersForRotation.json` - Browser headers for rotation[file:1]

## Requirements

- Python 3.8+
- `pip install requests stem`
- System Tor binary

## Usage

```bash
python3 z3rgRush.py -t "https://example.com/SWARM" -w wordlist.txt -c 3
```

**Options:**
- `-t` Target URL (use `SWARM` as fuzz point)
- `-w` Wordlist file
- `-c` Tor circuits (1-16, default 3)
- `-f` File extensions list or single extension
- `--post-data` Use wordlist as POST body
- `--headers` JSON file or `Key:Value` pairs
- `-v` Verbose output
- `-rc` Return codes to collect (default 200)[file:5]

## Install

1. Put all files in one directory
2. `pip install requests stem`
3. Run `python3 z3rgRush.py -h`

Tor uses temporary data directories (auto cleaned).[file:4]

## Example

```bash
python3 z3rgRush.py -t "https://target.com/SWARM" -w dirs.txt -f exts.txt -c 5 -v
```

**Output:**

```bash
Circuit 0: Tor Process launched
...
------ Collected Results ------
{'Circuit': 2, 'method': 'GET', 'port': 9053, 'IP': '185.220.101.XX', 'status': 200, 'len': 1234, 'fURL': 'https://target.com/admin.php'}
```


## Notes

- Max 16 circuits (uses system resources)
- Retries failed/rate-limited requests
- NEWNYM signal between retries

**Author:** derErntehelfer


