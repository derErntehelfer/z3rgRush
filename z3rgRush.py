#!/usr/bin/env python3
import argparse
import sys
from urllib.parse import urlparse

from circuitOvermind import circuitOvermind
from payloadFactory import payloadFactory
from torCircuitFactory import torCircuitFactory


def validateArguments(url, circuits, workers):
    parsed = urlparse(url)
    maxCircuits = 16

    if not parsed.scheme or parsed.scheme not in ("http", "https"):
        print(
            f"Error: URL must start with http:// or https:// ('{url}')",
            file=sys.stderr,
        )
        sys.exit(1)

    if circuits < 1 or circuits > maxCircuits:
        print(
            f"Error: --circuits must be between 1 and {maxCircuits}",
            file=sys.stderr,
        )
        sys.exit(1)

    if workers is None:
        return min(16, circuits)

    if workers > circuits:
        print(
            f"Warning: limiting workers to {circuits} (same as circuits).",
            file=sys.stderr,
        )
        return circuits

    return workers


def main():
    parser = argparse.ArgumentParser(description="z3rgRush - Tor-powered web fuzzer")
    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Target website URL (use {SWARM} as fuzz parameter)",
    )
    parser.add_argument(
        "-w",
        "--wordlist",
        required=True,
        help="Path to wordlist file",
    )
    parser.add_argument(
        "-c",
        "--circuits",
        type=int,
        default=3,
        help="Number of Tor circuits (default: 3)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Number of concurrent workers (threads); defaults to number of circuits",
    )
    parser.add_argument(
        "-f",
        "--filetype",
        default=None,
        help="Add file extension(s) to SWARM; either a single extension (e.g. '.php') or a wordlist path (one extension per line)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP request timeout in seconds (default: 10.0)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output (bootstrap-phase logs)",
    )

    args = parser.parse_args()
    args.workers = validateArguments(args.target, args.circuits, args.workers)

    art = [
        "||--------------------||",
        "||",
        "||     ▄▖    ▄▖    ▌",
        "||   ▀▌▄▌▛▘▛▌▙▘▌▌▛▘▛▌",
        "||   ▙▖▄▌▌ ▙▌▌▌▙▌▄▌▌▌",
        "||         ▄▌",
        "||",
        "||--------------------||",
        "||",
        "||   written by",
        "||    @derErntehelfer",
        "||",
        "||--------------------||",
        "",
    ]
    print("\n".join(art))

    torFactory = torCircuitFactory(
        numberOfCircuits=args.circuits,
        verbose=args.verbose,
    )
    _payloadFactory = payloadFactory()
    overmind = circuitOvermind(torFactory)

    try:
        payloads = _payloadFactory.generatePayloads(
            args.target,
            args.wordlist,
            filetypeArg=args.filetype,
        )
        overmind.sendPayloads(
            payloads,
            workers=args.workers,
            timeout=args.timeout,
        )
    except KeyboardInterrupt:
        print("\nCtrl+C received, shutting down Tor circuits...")
    except Exception as e:
        print(f"Aborting: {e}", file=sys.stderr)
    finally:
        torFactory.cleanupAll()
        print("Cleanup done, exiting.", file=sys.stderr)


if __name__ == "__main__":
    main()
