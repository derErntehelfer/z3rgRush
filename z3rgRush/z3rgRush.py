#!/usr/bin/env python3
import argparse
import sys
import os
import json
import threading
import signal
import logging

try:
    import argcomplete
except ImportError:
    argcomplete = None

from urllib.parse import urlparse

from circuitOvermind import circuitOvermind
from payloadFactory import payloadFactory
from torCircuitFactory import torCircuitFactory
from logger import console

logger = logging.getLogger("z3rgRush.main")

exitEvent = threading.Event()
interruptEvent = threading.Event()


def validateArguments(args):
    parsed = urlparse(args.target)
    maxCircuits = 16

    if not parsed.scheme or parsed.scheme not in ("http", "https"):
        logger.error(f"URL must start with http:// or https:// ('{args.target}')")
        sys.exit(1)

    if not parsed.netloc:
        logger.error(f"URL has no host/netloc: '{args.target}'")
        sys.exit(1)

    if "#" in args.target:
        fragment = args.target.split("#", 1)[1]

        if "{SWARM}" in fragment:
            logger.warning(
                "{SWARM} appears in URL fragment. "
                "HTTP clients do not send fragments to the server."
            )

    hasSwarmInUrl = "{SWARM}" in args.target
    hasSwarmInBody = args.body is not None and "{SWARM}" in args.body

    if not args.post_data and not hasSwarmInUrl and not hasSwarmInBody:
        logger.error(
            "The '{SWARM}' placeholder must be present in the target URL "
            "or the body template (-d), or use --post-data to use wordlist "
            "entries as the body."
        )
        sys.exit(1)

    if args.circuits < 1 or args.circuits > maxCircuits:
        logger.error(f"--circuits must be between 1 and {maxCircuits}")
        sys.exit(1)

    if args.timeout is None or args.timeout <= 0:
        logger.error("--timeout must be greater than 0")
        sys.exit(1)

    if args.workers is not None and args.workers < 1:
        logger.error("--workers must be at least 1")
        sys.exit(1)

    workers = args.workers

    if workers is None:
        workers = max(16, args.circuits * 10)
        logger.info(f"Auto-configured {workers} workers for {args.circuits} circuits.")

    if args.use_exit_proxy and workers > 1:
        logger.info(
            "--use-exit-proxy now uses local sidecar sockets. "
            "Workers can remain enabled."
        )

    return workers


def parseHeadersArg(headersArg):
    if not headersArg:
        default_file = "headersForRotation.json"

        if os.path.exists(default_file):
            logger.info(f"Using default headers file: {default_file}")

            try:
                with open(default_file, "r") as f:
                    config = json.load(f)

                return {
                    "file": default_file,
                    "config": config,
                    "custom": {},
                }

            except json.JSONDecodeError as err:
                logger.error(f"Invalid JSON in {default_file}: {err}")
                sys.exit(1)

            except OSError as err:
                logger.error(f"Could not read {default_file}: {err}")
                sys.exit(1)

        logger.info("No headers.json found, using empty header rotation")

        return {
            "file": None,
            "config": {},
            "custom": {},
        }

    if len(headersArg) == 1 and headersArg[0].endswith(".json"):
        headersFile = headersArg[0]

        if not os.path.isfile(headersFile):
            logger.error(f"Headers file not found: {headersFile}")
            sys.exit(1)

        logger.info(f"Loading headers from: {headersFile}")

        try:
            with open(headersFile, "r") as f:
                config = json.load(f)

            return {
                "file": headersFile,
                "config": config,
                "custom": {},
            }

        except json.JSONDecodeError as err:
            logger.error(f"Invalid JSON in {headersFile}: {err}")
            sys.exit(1)

        except OSError as err:
            logger.error(f"Could not read {headersFile}: {err}")
            sys.exit(1)

    customHeaders = {}

    for header in headersArg:
        if ":" in header:
            key, value = header.split(":", 1)
            customHeaders[key.strip()] = value.strip()
        else:
            logger.warning(f"Invalid header format '{header}' (expected 'Key:Value')")

    return {
        "file": None,
        "config": None,
        "custom": customHeaders,
    }


def parseReturnCodes(rawCodes):
    codes = set()

    try:
        for rawCode in rawCodes or ["200"]:
            for part in str(rawCode).split(","):
                part = part.strip()

                if not part:
                    continue

                codes.add(int(part))

    except ValueError:
        logger.error(
            "Invalid return code. Expected numeric HTTP status codes, "
            "for example: -rc 200 301 403"
        )
        sys.exit(1)

    if not codes:
        codes = {200}

    return sorted(codes)


def main():
    torFactory = None
    overmind = None
    exitCode = 0

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
        help="Number of concurrent workers (threads)",
    )

    parser.add_argument(
        "-f",
        "--filetype",
        default=None,
        help="Add file extension(s) to SWARM; either a single extension or a wordlist path",
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
        help="Enable verbose output",
    )

    parser.add_argument(
        "-m",
        "--method",
        default=None,
        choices=["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH"],
        help="HTTP method to use. Defaults to GET, or POST when body/data is used.",
    )

    parser.add_argument(
        "--post-data",
        action="store_true",
        default=False,
        help="Use wordlist entries as POST data instead of URL fuzzing",
    )

    parser.add_argument(
        "-d",
        "--body",
        default=None,
        help="Request body template. Use {SWARM} as the injection point.",
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
        help="Use additional exit proxies to hide Tor exit nodes (experimental)",
    )

    parser.add_argument(
        "-r",
        "--recursion",
        type=int,
        default=0,
        help="Set recursion depth on hits",
    )

    if argcomplete is not None:
        argcomplete.autocomplete(parser)

    args = parser.parse_args()

    args.workers = validateArguments(args)

    if not os.path.isfile(args.wordlist):
        logger.error(f"Wordlist not found: {args.wordlist}")
        sys.exit(1)

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
    customHeaders = headersInfo.get("custom", {}) or {}

    returnCodes = parseReturnCodes(args.return_codes)

    try:
        try:
            import socks  # noqa: F401
        except ImportError:
            try:
                import pyChainedProxy as socks  # noqa: F401
            except ImportError:
                raise RuntimeError(
                    "Missing SOCKS support. Install PySocks or requests[socks]."
                )

        torFactory = torCircuitFactory(
            numberOfCircuits=args.circuits,
            verbose=args.verbose,
        )

        payloadFactoryInstance = payloadFactory(
            args.wordlist,
            args.recursion,
        )

        filetypes = payloadFactoryInstance.loadFiletypes(args.filetype)

        overmind = circuitOvermind(
            torFactory,
            headersInfo=headersInfo,
            verbose=args.verbose,
            returnCodes=returnCodes,
            proxySet=args.use_exit_proxy,
            payloadFactoryInstance=payloadFactoryInstance,
            recursion=args.recursion,
        )

        def handleRecursion(roundDepth):
            newTargets = overmind.getHitsForRecursion()

            if interruptEvent.is_set():
                logger.warning("Interrupted: Skipping recursion.")
                return

            overmind.cleanUrlListInRecursion()

            if not newTargets:
                logger.info(
                    "No new hits collected on recursion, "
                    "ending before depth limit is reached"
                )
                raise StopIteration

            logger.info(f"Entering recursive fuzzing, current depth: {roundDepth + 1}")

            for url in newTargets:
                recursionPayloads = payloadFactoryInstance.iteratePayloads(
                    target=url,
                    filetypes=filetypes,
                    method=args.method,
                    postData=args.post_data,
                    bodyTemplate=args.body,
                )

                overmind.sendPayloads(
                    recursionPayloads,
                    workers=args.workers,
                    timeout=args.timeout,
                    postData=args.post_data,
                    customHeaders=customHeaders,
                    exitEvent=exitEvent,
                )

        payloadGenerator = payloadFactoryInstance.iteratePayloads(
            target=args.target,
            filetypes=filetypes,
            method=args.method,
            postData=args.post_data,
            bodyTemplate=args.body,
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
            for roundDepth in range(args.recursion):
                try:
                    handleRecursion(roundDepth)
                except StopIteration:
                    break

    except KeyboardInterrupt:
        logger.warning("Ctrl+C received, shutting down Tor circuits...")
        exitEvent.set()
        exitCode = 130

    except Exception as err:
        logger.error(f"Aborting: {err}")
        exitCode = 1

    finally:
        exitEvent.set()

        if overmind is not None:
            try:
                overmind.closeSidecars()
            except Exception as err:
                logger.error(f"Failed sidecar cleanup: {err}")

            try:
                overmind.printCollectedOutput()
            except Exception as err:
                logger.error(f"Failed printing collected output: {err}")

        if torFactory is not None:
            try:
                torFactory.cleanupAll()
            except Exception as err:
                logger.error(f"Failed Tor cleanup: {err}")

        logger.info("Cleanup done, exiting.")

        forceExit = threading.Timer(3.0, os._exit, args=[exitCode])
        forceExit.daemon = True
        forceExit.start()

        sys.exit(exitCode)


if __name__ == "__main__":
    main()
