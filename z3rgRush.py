#!/usr/bin/env python3
import argparse
import concurrent.futures
import shutil
import socket
import tempfile
import time
import os
import sys
import requests
from stem import Signal
from stem.control import Controller
from stem.process import launch_tor_with_config
from contextlib import suppress
from urllib.parse import urlparse


def findFreePort():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("", 0))
        return sock.getsockname()[1]


def validateUrl(url):
    parsed = urlparse(url)
    if not parsed.scheme or parsed.scheme not in ("http", "https"):
        print(
            f"Error: URL must start with http:// or https:// ('{url}')", file=sys.stderr
        )
        sys.exit(1)


def iter_payloads(target, wordlist_path, filetypes=None):
    filetypes = filetypes or [""]
    with open(wordlist_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            path = line.strip()
            if not path:
                continue
            for ext in filetypes:
                if ext.startswith("."):
                    ext = ext.lstrip(".")
                path_full = path + (("." + ext) if ext else "")
                yield target.replace("{SWARM}", path_full, 1)


class TorFactory:
    def __init__(self, numberOfCircuits=3, verbose=False):
        MAX_CIRCUITS = 16
        # Verbose flag for detailed output/debug
        self.verbose = verbose

        # Container Structures to collect Tor Circuits
        self.circuits = []
        self.dataDirs = []
        self.work = []

        if numberOfCircuits < 1 or numberOfCircuits > MAX_CIRCUITS:
            print(
                f"Error: --circuits must be between 1 and {MAX_CIRCUITS}",
                file=sys.stderr,
            )
            sys.exit(1)

        # Generate Circuits by collecting free ports, place config in temp file Structures
        for currentCircuitNr in range(numberOfCircuits):
            socksPort = findFreePort()
            controlPort = findFreePort()
            dataDir = tempfile.mkdtemp()
            self.dataDirs.append(dataDir)

            torConfig = {
                "SocksPort": str(socksPort),
                "ControlPort": str(controlPort),
                "DataDirectory": dataDir,
                "CookieAuthentication": "1",
                "ExitPolicy": "reject *:*",
                "Log": ["NOTICE stdout"] if verbose else [],
            }

            try:
                torProc = launch_tor_with_config(config=torConfig)
            except Exception as e:
                print(
                    f"Error starting Tor process for circuit {currentCircuitNr}: {e}",
                    file=sys.stderr,
                )
                self.cleanupAll()
                sys.exit(1)

            controller = Controller.from_port(port=controlPort)
            try:
                controller.authenticate()
            except Exception as e:
                print(
                    f"Error authenticating controller on port {controlPort}: {e}",
                    file=sys.stderr,
                )
                controller.close()
                torProc.kill()
                self.cleanupSingle(dataDir)
                sys.exit(1)

            self.waitForBootstrap(controller, currentCircuitNr)
            self.circuits.append((torProc, controller, socksPort, dataDir))

    def waitForBootstrap(self, controller, currentCircuitNr):
        while True:
            status = controller.get_info("status/bootstrap-phase")
            print(f"Circuit {currentCircuitNr}: {status}")
            if "100" in status:
                break
            time.sleep(1)

    def fetchWithCircuit(self, fuzzed, circuitIndex, timeout=10):
        torProc, controller, socksPort, dataDir = self.circuits[circuitIndex]

        proxies = {
            "http": f"socks5h://127.0.0.1:{socksPort}",
            "https": f"socks5h://127.0.0.1:{socksPort}",
        }

        controller.signal(Signal.NEWNYM)
        time.sleep(0.5)

        try:
            ip_resp = requests.get(
                "http://httpbin.org/ip", proxies=proxies, timeout=timeout
            )
            exit_ip = ip_resp.json().get("origin", "unknown")
        except Exception as ip_err:
            exit_ip = f"IP fetch error: {ip_err}"

        try:
            resp = requests.get(fuzzed, proxies=proxies, timeout=timeout)
            print(
                f"Circuit {circuitIndex} (port {socksPort}): "
                f"IP={exit_ip}, status={resp.status_code}, len={len(resp.content)} "
                f"-> URL: {fuzzed}"
            )
            return (True, None)
        except Exception as e:
            print(
                f"Circuit {circuitIndex} (port {socksPort}): "
                f"IP={exit_ip}, error -> {e} "
                f"(URL: {fuzzed})"
            )
            print(f"Payload {fuzzed} returned to Work Container")
            return (False, fuzzed)

    def loadFiletypes(self, filetype_arg):
        if not filetype_arg:
            return [""]
        if os.path.isfile(filetype_arg):
            try:
                with open(filetype_arg, "r") as f:
                    extensions = [line.strip() for line in f if line.strip()]
                if not extensions:
                    print(f"Error: {filetype_arg} is empty.", file=sys.stderr)
                    sys.exit(1)
                return extensions
            except Exception as e:
                print(f"Error reading {filetype_arg}: {e}", file=sys.stderr)
                sys.exit(1)
        # Treat as a single extension if not a file
        return [filetype_arg]

    def generatePayloads(
        self,
        target,
        wordlist_path,
        max_workers=None,
        filetype_arg=None,
        timeout=10,
    ):
        if max_workers is None:
            max_workers = min(16, len(self.circuits))

        if max_workers > len(self.circuits):
            print(
                f"Warning: limiting workers to {len(self.circuits)} (same as circuits).",
                file=sys.stderr,
            )
            max_workers = len(self.circuits)

        filetypes = self.loadFiletypes(filetype_arg)
        self.work = list(iter_payloads(target, wordlist_path, filetypes))
        # Prepare (fuzzedTarget, circuitIndex) for each request
        # Flatten all (path + filetype) into a single list

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as exec:
            futures = [
                exec.submit(
                    self.fetchWithCircuit,
                    fuzzed,
                    circuitIndex=i % len(self.circuits),
                )
                for i, fuzzed in enumerate(self.work)
            ]
            # Process results & retry failed ones
            for future in concurrent.futures.as_completed(futures):
                success, failed_payload = future.result()
                if not success and failed_payload:
                    self.work.append(failed_payload)

            concurrent.futures.wait(futures)

    def cleanupSingle(self, dataDir):
        with suppress(Exception):
            shutil.rmtree(dataDir, ignore_errors=True)

    def cleanupAll(self):
        for torProc, controller, socksPort, dataDir in self.circuits:
            with suppress(Exception):
                controller.close()
            if torProc is not None:
                try:
                    torProc.wait(timeout=5)
                except Exception:
                    try:
                        torProc.kill()
                        torProc.wait(timeout=1)
                    except Exception:
                        pass
            self.cleanupSingle(dataDir)

    def close(self):
        for torProc, controller, socksPort, dataDir in self.circuits:
            self.cleanupAll()


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
        help="Enable verbose output (bootstrap‑phase logs)",
    )

    args = parser.parse_args()
    validateUrl(args.target)
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
    factory = TorFactory(
        numberOfCircuits=args.circuits,
        verbose=args.verbose,
    )

    try:
        factory.generatePayloads(
            args.target,
            args.wordlist,
            max_workers=args.workers,
            filetype_arg=args.filetype,
            timeout=args.timeout,
        )
    except KeyboardInterrupt:
        print("\nCtrl+C received, shutting down Tor circuits...")
    except Exception as e:
        print(f"Aborting: {e}", file=sys.stderr)
    finally:
        factory.cleanupAll()
        print("Cleanup done, exiting.", file=sys.stderr)


if __name__ == "__main__":
    main()
