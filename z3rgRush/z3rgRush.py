#!/usr/bin/env python3
import argparse
import sys
import os
import json
import threading
import time
import subprocess
import signal
import atexit
from urllib.parse import urlparse

from circuitOvermind import circuitOvermind
from payloadFactory import payloadFactory
from torCircuitFactory import torCircuitFactory

exitEvent = threading.Event()


def suppressTerminalOutput():
    subprocess.run(["stty", "-echoctl"], check=False)
    atexit.register(lambda: subprocess.run(["stty", "echoctl"], check=False))


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


def parseHeadersArg(headersArg):
    if not headersArg:
        # Default: use headers.json if it exists
        default_file = "headersForRotation.json"
        if os.path.exists(default_file):
            print(f"z3rgRush: Using default headers file: {default_file}")
            with open(default_file, "r") as f:
                return {"file": default_file, "config": json.load(f)}
        else:
            print("z3rgRush: No headers.json found, using empty header rotation")
            return {"file": None, "config": {}}

    # Single argument - check if it's a JSON file
    if (
        len(headersArg) == 1
        and os.path.exists(headersArg[0])
        and headersArg[0].endswith(".json")
    ):
        headersFile = headersArg[0]
        print(f"Loading headers from: {headersFile}")
        try:
            with open(headersFile, "r") as f:
                config = json.load(f)
            return {"file": headersFile, "config": config}
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in {headersFile}: {e}", file=sys.stderr)
            sys.exit(1)

    # Multiple arguments or single non-JSON, treat as custom headers
    customHeaders = {}
    for h in headersArg:
        if ":" in h:
            key, value = h.split(":", 1)
            customHeaders[key.strip()] = value.strip()
        else:
            print(
                f"Warning: Invalid header format '{h}' (expected 'Key:Value')",
                file=sys.stderr,
            )

    return {"file": None, "config": None, "custom": customHeaders}


def main():
    # suppressTerminalOutput()
    parser = argparse.ArgumentParser(
        description="z3rgRush - Tor-powered web fuzzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    z3rgRush -t "http://example.com/SWARM" -w wordlist.txt
    z3rgRush -t "https://target.com/SWARM" -w dirs.txt -f exts.txt -c 5 --workers 10
    z3rgRush -t "http://test.com/SWARM" -w files.txt --post-data
""",
    )
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
    parser.add_argument(
        "--post-data",
        action="store_true",
        default=None,
        help="Use wordlist entries as POST data instead of URL fuzzing",
    )
    parser.add_argument(
        "--headers",
        nargs="*",
        default=[],
        help="""Headers config:
        - JSON file path (e.g. --headers headers.json)
        - Default uses headers.json if present
        - OR individual headers: --headers 'Key:Value' 'Key2:Value2'""",
    )
    parser.add_argument(
        "-rc",
        "--return-codes",
        nargs="*",
        default=[200],
        help="HTTP status codes considered successful (default: 200)",
    )
    parser.add_argument(
        "-ep",
        "--use-exit-proxy",
        action="store_true",
        default=False,
        help="Use additonal Exit proxies to hide Tor Exit Nodes (experimental)",
    )
    parser.add_argument(
        "-r",
        "--recursion",
        type=int,
        default=0,
        help="Set Recursion on hits, Value sets Depth of Recursion",
    )

    def handleRecursion(round):
        for url in newTargets:
            recursionPayloads = payloadFactoryInstance.iteratePayloads(
                url,
                filetypes,
                args.post_data,
            )
            overmind.sendPayloads(
                recursionPayloads,
                workers=args.workers,
                timeout=args.timeout,
                postData=args.post_data,
                customHeaders=customHeaders,
                exitEvent=exitEvent,
            )

    args = parser.parse_args()
    args.workers = validateArguments(args.target, args.circuits, args.workers)

    def handleSigint(signum, frame):
        exitEvent.set()

    signal.signal(signal.SIGINT, handleSigint)

    # Parse custom headers
    customHeaders = {}
    for h in args.headers:
        if ":" in h:
            key, value = h.split(":", 1)
            customHeaders[key.strip()] = value.strip()

    art = [
        " ",
        "======================================================================",
        "##  ███████╗██████╗ ██████╗  ██████╗ ██████╗ ██╗   ██╗███████╗██╗  ██╗",
        "##  ╚══███╔╝╚════██╗██╔══██╗██╔════╝ ██╔══██╗██║   ██║██╔════╝██║  ██║",
        "##    ███╔╝  █████╔╝██████╔╝██║  ███╗██████╔╝██║   ██║███████╗███████║",
        "##   ███╔╝   ╚═══██╗██╔══██╗██║   ██║██╔══██╗██║   ██║╚════██║██╔══██║",
        "##  ███████╗██████╔╝██║  ██║╚██████╔╝██║  ██║╚██████╔╝███████║██║  ██║",
        "##  ╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝",
        "======================================================================",
        "                                                 ## by @derErntehelfer",
        "                                                 =====================",
        " ",
    ]

    print("\n".join(art))
    headersInfo = parseHeadersArg(args.headers)
    try:
        torFactory = torCircuitFactory(
            numberOfCircuits=args.circuits,
            verbose=args.verbose,
        )
    except OSError as osError:
        print(f"z3rgRush: Could not build Circuits: {osError}")
        exitEvent.set()
        sys.exit(1)
    except RuntimeError as runError:
        print(f"z3rgRush: Could not build Circuits: {runError}")
        exitEvent.set()
        sys.exit(1)

    payloadFactoryInstance = payloadFactory(args.wordlist, args.recursion)
    filetypes = payloadFactoryInstance.loadFiletypes(args.filetype)
    overmind = circuitOvermind(
        torFactory,
        headersInfo=headersInfo,
        verbose=args.verbose,
        returnCodes=[int(code.replace(",", "").strip()) for code in args.return_codes],
        proxySet=args.use_exit_proxy,
        payloadFactoryInstance=payloadFactoryInstance,
        recursion=args.recursion,
    )

    try:
        payloadGenerator = payloadFactoryInstance.iteratePayloads(
            args.target,
            filetypes,
            args.post_data,
        )

        overmind.sendPayloads(
            payloadGenerator,
            workers=args.workers,
            timeout=args.timeout,
            postData=args.post_data,
            customHeaders=customHeaders,
            exitEvent=exitEvent,
        )
        if exitEvent is not None:
            for round in range(0, args.recursion):
                newTargets = overmind.getHitsForRecursion()
                if newTargets != []:
                    print(
                        f"z3rgRush: Entering Recursive Fuzzing, current depth: {round + 1}"
                    )
                    handleRecursion(round)
                    overmind.cleanUrlListInRecursion()
                elif newTargets == []:
                    print(
                        "z3rgRush: No new hits collected on Recursion, ending before end of Depth is reached"
                    )
                    break

    except KeyboardInterrupt:
        print("\nCtrl+C received, shutting down Tor circuits...")
        exitEvent.set()
    except Exception as e:
        print(f"Aborting: {e}", file=sys.stderr)
    finally:
        exitEvent.set()
        overmind.printCollectedOutput()
        torFactory.cleanupAll()
        print("Cleanup done, exiting.", file=sys.stderr)

        time.sleep(1)
        os._exit(0)


if __name__ == "__main__":
    main()
