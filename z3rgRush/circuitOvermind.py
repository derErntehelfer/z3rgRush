import concurrent.futures
import random
import socket
import sys
import time
import builtins
import subprocess
import threading

# import logging
import requests
from stem import Signal


# Import based on Proxy or Tor Mode
try:
    import socks
except ImportError:
    try:
        import pyChainedProxy as socks

        sys.modules["socks"] = socks
    except ImportError:
        pass


def quietPrint(*args, **kwargs):
    msg = " ".join(str(arg) for arg in args)
    if "Python 3" not in msg:
        builtins._original_print(*args, **kwargs)


class circuitOvermind:
    def __init__(
        self,
        torFactory,
        headersInfo=None,
        verbose=False,
        returnCodes=[200],
        proxySet=False,
        payloadFactoryInstance=None,
        recursion=0,
    ):
        self.torFactory = torFactory
        self.sessions = {}
        for circuits in range(len(self.torFactory.circuits)):
            session = requests.Session()
            self.sessions[circuits] = session

        self.headerIndex = 0
        self.returnCodes = returnCodes
        self.verbose = verbose
        self.collectedOutput = []
        self.useProxyExit = proxySet
        self.hitsFromReturnCode = []
        self.recursion = recursion

        self.circuitIps = {i: "Unknown" for i in range(len(self.torFactory.circuits))}
        self.circuitLastStatus = {i: None for i in range(len(self.torFactory.circuits))}
        self.circuitLock = threading.Lock()
        self.headerLock = threading.Lock()

        # Status codes that indicate rate-limiting, WAF blocks, or connection issues
        self.codesForRotation = {403, 429, 430, 440, 449, 503, 521, 523, 524, 502, 504}

        if self.useProxyExit:
            self.upstreamProxies = self.collectProxyscrapeProxies()
            self.badProxies = set()
            print(f"Overmind: Collected {len(self.upstreamProxies)} upstream proxies")

        # REMOVED: Global socket monkey-patching is now handled conditionally in fetchWithCircuit

        if headersInfo and headersInfo.get("config"):
            self.headerSets = headersInfo["config"]
            print(
                f"Overmind: Loaded {len(self.headerSets.get('user_agents', []))} UAs from {headersInfo['file']}"
            )
        else:
            # Fallback to empty/minimal
            self.headerSets = {
                "user_agents": ["Mozilla/5.0 (compatible; z3rgRush/1.0)"],
                "accept_headers": ["*/*"],
                "accept_languages": ["en-US,en;q=0.9"],
                "accept_encodings": ["gzip, deflate, br"],
                "referers": ["https://www.google.com/"],
                "sec_fetch_dest": ["document"],
                "sec_fetch_mode": ["navigate"],
                "sec_fetch_site": ["same-origin"],
                "sec_ch_ua_mobile": ["?0"],
                "sec_ch_ua_platforms": ['"Windows"'],
            }
            print("No headers config loaded, using minimal defaults")

    def collectProxyscrapeProxies(self):
        curlCmd = [
            "curl",
            "-s",
            "https://api.proxyscrape.com/v4/free-proxy-list/get?protocol=http&timeout=10000&country=all&ssl=all&anonymity=all&limit=2000&request=displayproxies",
        ]

        try:
            result = subprocess.run(curlCmd, capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                proxyLines = [
                    line.strip()
                    for line in result.stdout.strip().split("\n")
                    if ":" in line
                ]

                proxies = []
                for line in proxyLines:
                    if ":" in line:
                        ip, port = line.rsplit(":", 1)
                        proxies.append(f"http://{ip}:{port}")

                return proxies[:50]
        except Exception as e:
            print(f"Proxy collection failed: {e}")

    def getNextHeaders(self):
        with self.headerLock:
            self.headerIndex += 1
            rotationIndex = self.headerIndex % 100

        userAgentIndex = rotationIndex % len(self.headerSets["user_agents"])
        acceptIndex = (rotationIndex + 1) % len(self.headerSets["accept_headers"])
        languageIndex = (rotationIndex + 2) % len(self.headerSets["accept_languages"])
        encodingIndex = (rotationIndex + 3) % len(self.headerSets["accept_encodings"])
        refererIndex = (rotationIndex + 4) % len(self.headerSets["referers"])
        fetchIndex = (rotationIndex + 5) % 4

        headers = {
            "User-Agent": self.headerSets["user_agents"][userAgentIndex],
            "Accept": self.headerSets["accept_headers"][acceptIndex],
            "Accept-Language": self.headerSets["accept_languages"][languageIndex],
            "Accept-Encoding": self.headerSets["accept_encodings"][encodingIndex],
            "Referer": self.headerSets["referers"][refererIndex],
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": self.headerSets["sec_fetch_dest"][
                fetchIndex % len(self.headerSets["sec_fetch_dest"])
            ],
            "Sec-Fetch-Mode": self.headerSets["sec_fetch_mode"][
                fetchIndex % len(self.headerSets["sec_fetch_mode"])
            ],
            "Sec-Fetch-Site": self.headerSets["sec_fetch_site"][
                fetchIndex % len(self.headerSets["sec_fetch_site"])
            ],
            "Sec-Fetch-User": "?1",
            "Sec-CH-UA": '"Chromium";v="129", "Not=A?Brand";v="24", "Google Chrome";v="129"',
            "Sec-CH-UA-Mobile": self.headerSets["sec_ch_ua_mobile"][
                userAgentIndex % len(self.headerSets["sec_ch_ua_mobile"])
            ],
            "Sec-CH-UA-Platform": self.headerSets["sec_ch_ua_platforms"][
                userAgentIndex % len(self.headerSets["sec_ch_ua_platforms"])
            ],
        }
        return headers

    def printHeadersVerbose(self, headers):
        if not self.verbose:
            return
        print("  Headers:")
        for key, value in headers.items():
            print(f"    {key}: {value}")

    def getExitIp(self, proxies, timeout, headers):
        endpoints = [
            ("https://api.ipify.org?format=json", lambda r: r.json().get("ip")),
            ("https://httpbin.org/ip", lambda r: r.json().get("origin")),
            ("https://ifconfig.me/ip", lambda r: r.text.strip()),
        ]

        for url, parser in endpoints:
            try:
                ipResponse = requests.get(
                    url,
                    proxies=proxies,
                    timeout=timeout,
                    headers=headers,
                )
                ipResponse.raise_for_status()
                exitIp = parser(ipResponse)
                if exitIp and "," in exitIp:
                    exitIp = exitIp.split(",")[0].strip()
                if exitIp:
                    return exitIp
            except Exception:
                continue
        return "IP fetch error"

    def rotateCircuit(self, circuitIndex, reason=None):
        """Rotate the Tor circuit for the given circuit index"""
        torProcess, controller, socksPort, dataDir = self.torFactory.circuits[
            circuitIndex
        ]
        try:
            controller.signal(Signal.NEWNYM)
            time.sleep(1.5)  # Wait longer for circuit to establish

            # FIX: Always print if triggered by an error (reason provided), otherwise respect verbose flag
            if reason or self.verbose:
                reason_str = f" (Reason: {reason})" if reason else ""
                print(
                    f"Overmind: Circuit {circuitIndex} rotated successfully{reason_str}"
                )
        except Exception as e:
            raise RuntimeError(f"Failed to rotate Tor circuit: {e}") from e

    def fetchWithCircuit(
        self,
        requestSpec,
        circuitIndex,
        data=None,
        timeout=10,
        customHeaders=None,
        exitEvent=None,
        requestKwargs=None,
    ):
        torProcess, controller, socksPort, dataDir = self.torFactory.circuits[
            circuitIndex
        ]

        requestKwargs = requestKwargs or {}
        if exitEvent is not None and exitEvent.is_set():
            return False, requestSpec

        headers = self.getNextHeaders()
        if customHeaders:
            headers.update(customHeaders)

        url = requestSpec.get("url")
        method = requestSpec.get("method", "GET")
        data = requestSpec.get("data", None)

        if exitEvent and exitEvent.is_set():
            return False, requestSpec

        upstreamProxy = None
        exitIp = "Unknown"

        try:
            if self.useProxyExit:
                # ==========================================
                # EXIT PROXY PATH (Experimental)
                # Uses monkey-patching, protected by a Lock
                # ==========================================
                availableProxies = [
                    p for p in self.upstreamProxies if p not in self.badProxies
                ]
                if not availableProxies:
                    print("Overmind: All upstream proxies failed - refetching...")
                    self.upstreamProxies = self.collectProxyscrapeProxies()
                    self.badProxies.clear()
                    availableProxies = self.upstreamProxies

                upstreamProxy = random.choice(availableProxies)
                proxyDisplay = (
                    upstreamProxy.split("://")[1]
                    if "://" in upstreamProxy
                    else upstreamProxy
                )
                exitIp = f"Tor+Proxy({proxyDisplay})"

                import pyChainedProxy as chained_socks

                # Lock prevents threads from overwriting each other's proxy chains
                with self.circuitLock:
                    chain = [f"socks5://127.0.0.1:{socksPort}/", upstreamProxy + "/"]
                    chained_socks.setdefaultproxy()
                    for hop in chain:
                        chained_socks.adddefaultproxy(*chained_socks.parseproxy(hop))

                    original_socket = socket.socket
                    socket.socket = chained_socks.socksocket

                    try:
                        session = self.sessions[circuitIndex]
                        response = session.request(
                            method=method,
                            url=url,
                            headers=headers,
                            timeout=timeout,
                            data=data,
                            **requestKwargs,
                        )
                    finally:
                        socket.socket = original_socket  # Restore immediately

            else:
                # ==========================================
                # NATIVE PATH (Standard, Thread-Safe)
                # Uses native requests proxy support
                # ==========================================
                # socks5h:// forces DNS resolution over Tor (prevents DNS leaks)
                proxies = {
                    "http": f"socks5h://127.0.0.1:{socksPort}",
                    "https": f"socks5h://127.0.0.1:{socksPort}",
                }

                # FIX: Only fetch the IP if it's not already cached for this circuit
                if self.circuitIps[circuitIndex] == "Unknown":
                    self.circuitIps[circuitIndex] = self.getExitIp(
                        proxies, timeout, headers
                    )

                exitIp = self.circuitIps[circuitIndex]

                session = self.sessions[circuitIndex]
                response = session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    timeout=timeout,
                    data=data,
                    proxies=proxies,
                    **requestKwargs,
                )

            # --- LOGGING ---
            if self.verbose:
                if self.useProxyExit and upstreamProxy:
                    print(
                        f"Overmind: [CHAIN] Local --> Tor({socksPort}) --> Proxy({upstreamProxy}) --> Exit({exitIp}) --> {url}"
                    )
                else:
                    print(
                        f"Overmind: [CHAIN] Local --> Tor({socksPort}) --> Exit({exitIp}) --> {url}"
                    )

            resultToCollect = (
                f"Circuit {circuitIndex} ({method}) (port {socksPort}): "
                f"IP={exitIp}, status={response.status_code}, len={len(response.content)} "
                f"(URL: {url})"
            )
            print(resultToCollect)
            self.printHeadersVerbose(headers)

            # --- SUCCESS / RECURSION ---
            if response.status_code in self.returnCodes:
                self.collectedOutput.append(resultToCollect)
                if self.recursion >= 1:
                    self.hitsFromReturnCode.append((url + "/" + "{SWARM}"))
                return (True, None)

            # --- RATE LIMIT / WAF DETECTION ---
            if response.status_code in self.codesForRotation and not exitEvent.is_set():
                print(
                    f"Overmind: Rate limit/WAF detected (status {response.status_code}) on circuit {circuitIndex} - rotating circuit"
                )
                self.rotateCircuit(
                    circuitIndex, reason=f"WAF/Rate Limit ({response.status_code})"
                )
                print(
                    f"Overmind: Payload {url} returned to Work Container - Response Status {response.status_code}"
                )
                return (False, requestSpec)

            return (True, None)

        # --- ERROR HANDLING ---
        except requests.exceptions.Timeout:
            if not exitEvent.is_set():
                if self.useProxyExit and upstreamProxy:
                    self.badProxies.add(upstreamProxy)
                    print(
                        f"Overmind: [BAD PROXY] {upstreamProxy} timed out - blacklisted"
                    )

                print(f"Overmind: Payload {url} returned to Work Container - Timed out")
                self.rotateCircuit(circuitIndex, reason="Timeout")
            return (False, requestSpec)

        except requests.exceptions.ConnectionError as ce:
            if "refused" in str(ce).lower() or "reset" in str(ce).lower():
                if not exitEvent.is_set():
                    if self.useProxyExit and upstreamProxy:
                        self.badProxies.add(upstreamProxy)
                        print(
                            f"Overmind: [BAD PROXY] {upstreamProxy} connection refused/reset - blacklisted"
                        )

                    print(
                        f"Overmind: Payload {url} returned to Work Container - Connection refused"
                    )
                    self.rotateCircuit(circuitIndex, reason="Connection Refused/Reset")
            return (False, requestSpec)

        except Exception as e:
            if not exitEvent.is_set():
                # FIX: Blacklist the upstream proxy if it threw a generic/SOCKS error
                if self.useProxyExit and upstreamProxy:
                    self.badProxies.add(upstreamProxy)
                    print(
                        f"Overmind: [BAD PROXY] {upstreamProxy} threw error {e} - blacklisted"
                    )

                print(
                    f"Circuit {circuitIndex} ({method}) (port {socksPort}): IP={exitIp}, error -> {e} (URL: {url}) "
                )
                print(
                    f"Overmind: Payload {url} returned to Work Container - Failed to Send "
                )
                self.rotateCircuit(
                    circuitIndex, reason=f"Exception ({type(e).__name__})"
                )
            return (False, requestSpec)

    def sendPayloads(
        self,
        payloads,
        workers=None,
        timeout=10,
        postData=False,
        customHeaders=None,
        exitEvent=None,
    ):
        work = list(payloads)
        maxRetries = 3

        while work and maxRetries > 0 and (exitEvent is None or not exitEvent.is_set()):
            currentWork = work[:]
            work = []

            originalPrint = getattr(builtins, "_original_print", None)
            if originalPrint is None:
                builtins._original_print = builtins.print
                builtins.print = lambda *args, **kwargs: (
                    None
                    if "Python 3" in " ".join(map(str, args))
                    else builtins._original_print(*args, **kwargs)
                )

            executor = None
            futures = []
            try:
                executor = concurrent.futures.ThreadPoolExecutor(max_workers=workers)

                for i, payload in enumerate(currentWork):
                    if isinstance(payload, dict):
                        requestSpec = payload
                    elif postData and isinstance(payload, tuple):
                        url, postDataValue = payload
                        requestSpec = {
                            "url": url,
                            "data": postDataValue,
                            "method": "POST",
                            "payload": postDataValue,
                        }
                    else:
                        requestSpec = {
                            "url": payload,
                            "data": None,
                            "method": "GET",
                            "payload": payload,
                        }

                    futures.append(
                        executor.submit(
                            self.fetchWithCircuit,
                            requestSpec,
                            i % len(self.torFactory.circuits),
                            timeout=timeout,
                            customHeaders=customHeaders,
                            exitEvent=exitEvent,
                        )
                    )

                pending = set(futures)
                while pending:
                    if exitEvent is not None and exitEvent.is_set():
                        break

                    done, pending = concurrent.futures.wait(
                        pending,
                        timeout=0.5,
                        return_when=concurrent.futures.FIRST_COMPLETED,
                    )

                    for future in done:
                        success, failedPayload = future.result()
                        if (
                            not success
                            and failedPayload
                            and (exitEvent is None or not exitEvent.is_set())
                        ):
                            work.append(failedPayload)

                maxRetries -= 1

            except KeyboardInterrupt:
                if exitEvent is not None:
                    exitEvent.set()
            except Exception as e:
                print(f"sendPayloads failed: {e}")
                if exitEvent is not None:
                    exitEvent.set()
            finally:
                if executor is not None:
                    executor.shutdown(wait=False, cancel_futures=True)

        if work and (exitEvent is None or not exitEvent.is_set()):
            print(f"Failed payloads after {maxRetries} retries: {len(work)}")

    def getHitsForRecursion(self):
        return self.hitsFromReturnCode

    def cleanUrlListInRecursion(self):
        self.hitsFromReturnCode.clear()

    def printCollectedOutput(self):
        print("------ Collected Results ------")
        if self.collectedOutput != []:
            for outputs in self.collectedOutput:
                print(outputs)
        else:
            print("No Results Collected")
        print("------ Collected Results ------")
