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
import logging
from urllib.parse import urlparse

# Import logger and console first
from logger import setup_logging, console

logger = logging.getLogger("z3rgRush.main")

from circuitOvermind import circuitOvermind
from payloadFactory import payloadFactory
from torCircuitFactory import torCircuitFactory

exitEvent = threading.Event()
interruptEvent = threading.Event()


def suppressTerminalOutput():
    subprocess.run(["stty", "-echoctl"], check=False)
    atexit.register(lambda: subprocess.run(["stty", "echoctl"], check=False))


def validateArguments(url, circuits, workers, postData):
    parsed = urlparse(url)
    maxCircuits = 16
    if not parsed.scheme or parsed.scheme not in ("http", "https"):
        logger.error(f"URL must start with http:// or https:// ('{url}')")
        sys.exit(1)

    if not postData and "{SWARM}" not in url:
        logger.error(
            "Target URL must contain '{{SWARM}}' placeholder for GET fuzzing (e.g., http://target.com/{{SWARM}})"
        )
        sys.exit(1)

    if circuits < 1 or circuits > maxCircuits:
        logger.error(f"--circuits must be between 1 and {maxCircuits}")
        sys.exit(1)

    if workers is None:
        return min(16, circuits)
    if workers > circuits:
        logger.warning(f"Limiting workers to {circuits} (same as circuits).")
        return circuits
    return workers


def parseHeadersArg(headersArg):
    if not headersArg:
        default_file = "headersForRotation.json"
        if os.path.exists(default_file):
            logger.info(f"Using default headers file: {default_file}")
            with open(default_file, "r") as f:
                return {"file": default_file, "config": json.load(f)}
        else:
            logger.info("No headers.json found, using empty header rotation")
            return {"file": None, "config": {}}

    if (
        len(headersArg) == 1
        and os.path.exists(headersArg[0])
        and headersArg[0].endswith(".json")
    ):
        headersFile = headersArg[0]
        logger.info(f"Loading headers from: {headersFile}")
        try:
            with open(headersFile, "r") as f:
                config = json.load(f)
            return {"file": headersFile, "config": config}
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {headersFile}: {e}")
            sys.exit(1)

    customHeaders = {}
    for h in headersArg:
        if ":" in h:
            key, value = h.split(":", 1)
            customHeaders[key.strip()] = value.strip()
        else:
            logger.warning(f"Invalid header format '{h}' (expected 'Key:Value')")
    return {"file": None, "config": None, "custom": customHeaders}


def main():
    torFactory = None
    overmind = None

    parser = argparse.ArgumentParser(
        description="z3rgRush - Tor-powered web fuzzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  z3rgRush -t "http://example.com/{SWARM}" -w wordlist.txt
  z3rgRush -t "https://target.com/{SWARM}" -w dirs.txt -f exts.txt -c 5 --workers 10
  z3rgRush -t "http://test.com/{SWARM}" -w files.txt --post-data
""",
    )
    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Target website URL (use {SWARM} as fuzz parameter)",
    )
    parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist file")
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
        help="Add file extension(s) to SWARM; either a single extension (e.g. '.php') or a wordlist path",
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
        help="Headers config: JSON file path OR individual headers 'Key:Value'",
    )
    parser.add_argument(
        "-rc",
        "--return-codes",
        nargs="*",
        default=["200"],
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

    args = parser.parse_args()
    args.workers = validateArguments(
        args.target, args.circuits, args.workers, args.post_data
    )

    def handleSigint(signum, frame):
        interruptEvent.set()
        exitEvent.set()

    signal.signal(signal.SIGINT, handleSigint)

    art = [
        " ",
        "======================================================================",
        "##  ███████╗██████╗ ██████╗  ██████╗ ██████╗ ██╗   ██╗███████╗██╗  ██╗",
        "##  ╚══███╔╝╚════██╗██╔══██╗██╔════╝ ██╔══██╗██║   ██║██╔════╝██║  ██║",
        "##    ███╔╝  █████╔╝██████╔╝██║  ███╗██████╔╝██║   ██║███████╗███████║",
        "##   ███╔╝   ╚═══██╗██╔══██╗██║   ██║██╔══██╗██║   ██║╚════██║██╔══██║",
        "##  ███████╗██████╔╝██║  ██║╚██████╔╝██║  ██║╚██████╔╝███████║██║  ██║",
        "##  ╚══════╝╚═╝  ╚═╝ ╚═╝  ╚═╝ ╚═╝  ╚═╝ ╚═╝  ╚═╝ ╚═╝  ╚═╝ ╚══════╝  ╚═╝",
        "======================================================================",
        "                                                 ## by @derErntehelfer",
        "                                                 =====================",
        " ",
    ]
    console.print("\n".join(art), style="#7A98B5")

    headersInfo = parseHeadersArg(args.headers)
    customHeaders = headersInfo.get("custom", {})

    try:
        torFactory = torCircuitFactory(
            numberOfCircuits=args.circuits,
            verbose=args.verbose,
        )
    except KeyboardInterrupt:
        logger.warning("Interrupted during circuit building. Exiting...")
        sys.exit(0)
    except (OSError, RuntimeError) as e:
        logger.error(f"Could not build Circuits: {e}")
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

    def handleRecursion(round_depth):
        newTargets = overmind.getHitsForRecursion()
        if interruptEvent.is_set():
            logger.warning("Interrupted: Skipping recursion.")
            return
        elif newTargets:
            logger.info(f"Entering Recursive Fuzzing, current depth: {round_depth + 1}")
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
            overmind.cleanUrlListInRecursion()
        else:
            logger.info(
                "No new hits collected on Recursion, ending before end of Depth is reached"
            )
            raise StopIteration

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

        if args.recursion > 0:
            for round_depth in range(args.recursion):
                try:
                    handleRecursion(round_depth)
                except StopIteration:
                    break

    except KeyboardInterrupt:
        logger.warning("Ctrl+C received, shutting down Tor circuits...")
        exitEvent.set()
    except Exception as e:
        logger.error(f"Aborting: {e}")
    finally:
        exitEvent.set()
        if overmind is not None:
            overmind.printCollectedOutput()
        if torFactory is not None:
            torFactory.cleanupAll()
        logger.info("Cleanup done, exiting.")
        time.sleep(1)
        os._exit(0)


if __name__ == "__main__":
    main()
