import concurrent.futures
import random
import socket
import time
import builtins
import subprocess
import requests
import pyChainedProxy as socks
from stem import Signal
from urllib.parse import urlparse


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
        returnCodes=200,
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

        if self.useProxyExit:
            self.upstreamProxies = self.collectProxyscrapeProxies()
            self.badProxies = set()
            print(f"Overmind: Collected {len(self.upstreamProxies)} upstream proxies")

        socket.socket = socks.socksocket
        socks.setproxy("localhost", socks.PROXY_TYPE_NONE)
        socks.setproxy("127.0.0.1", socks.PROXY_TYPE_NONE)

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
        self.headerIndex += 1
        rotationIndex = self.headerIndex % 100

        userAgentIndex = rotationIndex % len(self.headerSets["user_agents"])
        acceptIndex = (rotationIndex + 1) % len(self.headerSets["accept_headers"])
        languageIndex = (rotationIndex + 2) % len(self.headerSets["accept_languages"])
        encodingIndex = (rotationIndex + 3) % len(self.headerSets["accept_encodings"])
        refererIndex = (rotationIndex + 4) % len(self.headerSets["referers"])
        fetchIndex = (rotationIndex + 5) % 4

        headers = {
            # Core rotation
            "User-Agent": self.headerSets["user_agents"][userAgentIndex],
            "Accept": self.headerSets["accept_headers"][acceptIndex],
            "Accept-Language": self.headerSets["accept_languages"][languageIndex],
            "Accept-Encoding": self.headerSets["accept_encodings"][encodingIndex],
            "Referer": self.headerSets["referers"][refererIndex],
            # Always static
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            # Rotating Sec-Fetch
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
            # Client Hints
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
        try:
            ipResponse = requests.get(
                "http://httpbin.org/ip",
                proxies=proxies,
                timeout=timeout,
                headers=headers,
            )
            exitIp = ipResponse.json().get("origin", "unknown")
            if "," in exitIp:
                exitIp.split(",")[0].strip()
        except Exception as ip_error:
            exitIp = f"IP fetch error: {ip_error}"
        return exitIp

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

        try:
            controller.signal(Signal.NEWNYM)
        except Exception as e:
            if exitEvent is not None and exitEvent.is_set():
                return False, requestSpec
            raise RuntimeError(f"Failed to rotate Tor circuit: {e}") from e
        time.sleep(0.5)
        codesForRetry = {429, 430, 440, 449, 503, 521, 523, 524}

        headers = self.getNextHeaders()
        if customHeaders:
            headers.update(customHeaders)

        url = requestSpec.get("url")
        method = requestSpec.get("method", "GET")
        data = requestSpec.get("data", None)
        if exitEvent and exitEvent.is_set():
            return False, requestSpec
        socks.DEBUG = lambda msg: print(f"SOCKS DEBUG: {msg}") if self.verbose else None

        if self.useProxyExit:
            if exitEvent is not None and exitEvent.is_set():
                return False, requestSpec

            availableProxies = [
                p for p in self.upstreamProxies if p not in self.badProxies
            ]
            if not availableProxies:
                print("Overmind: All upstream proxies failed - refetching...")
                self.upstreamProxies = self.collectProxyscrapeProxies()
                self.badProxies.clear()
                availableProxies = self.upstreamProxies
            upstreamProxy = random.choice(availableProxies)

            parsed = urlparse(upstreamProxy)
            if parsed.scheme and parsed.hostname and parsed.port:
                host = parsed.hostname
                port = parsed.port
            else:
                # Fallback: ip:port
                host, port_str = upstreamProxy.rsplit(":", 1)
                port = int(port_str)
                host = host.strip()[5:] if host.startswith("http") else host.strip()

            chain = [f"socks5://127.0.0.1:{socksPort}/", upstreamProxy + "/"]

        else:
            chain = [f"socks5://127.0.0.1:{socksPort}/"]

        socks.setdefaultproxy()  # Clear previous chain
        for hop in chain:
            socks.adddefaultproxy(*socks.parseproxy(hop))

        if self.useProxyExit and "upstreamProxy" in locals():
            exitIp = f"Tor+Proxy({upstreamProxy.split('://')[1] if '://' in upstreamProxy else upstreamProxy})"
            proxyChain = {"http": upstreamProxy, "https": upstreamProxy}
        else:
            exitIp = self.getExitIp({}, timeout, headers)
            proxyChain = {}

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

            if self.verbose and self.useProxyExit:
                print(
                    f"Overmind: [CHAIN] Local --> Tor({socksPort}) --> Proxy({upstreamProxy}) --> Exit({exitIp}) --> {url}"
                )
            elif self.verbose:
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

            if response.status_code in codesForRetry and not exitEvent.is_set():
                print(
                    f"Overmind: Payload {url} returned to Work Container - Response Status"
                )
                return (False, requestSpec)
            if response.status_code in self.returnCodes:
                self.collectedOutput.append(resultToCollect)
                if self.recursion >= 1:
                    self.hitsFromReturnCode.append((url + "/" + "{SWARM}"))

            return (True, None)

        except requests.exceptions.Timeout:
            if not exitEvent.is_set():
                if self.useProxyExit:
                    self.badProxies.add(upstreamProxy)
                    print(
                        f"Overmind: Payload {url} returned to Work Container - [BAD PROXY] {upstreamProxy} timed out - blacklisted"
                    )
                else:
                    print(
                        f"Overmind: Payload {url} returned to Work Container - Timed out"
                    )
            return (False, requestSpec)
        except requests.exceptions.ConnectionError as ce:
            if "refused" in str(ce).lower() or "reset" in str(ce).lower():
                if not exitEvent.is_set():
                    if self.useProxyExit:
                        self.badProxies.add(upstreamProxy)
                        print(
                            f"Overmind: Payload {url} returned to Work Container - [BAD PROXY] {upstreamProxy} connection refused/reset - blacklisted"
                        )
                    else:
                        print(
                            f"Overmind: Payload {url} returned to Work Container - Connection refused"
                        )

            return (False, requestSpec)
        except Exception as e:
            if not exitEvent.is_set():
                print(
                    f"Circuit {circuitIndex} ({method}) (port {socksPort}): "
                    f"IP={exitIp}, error -> {e} "
                    f"(URL: {url})"
                )
                print(
                    f"Overmind: Payload {url} returned to Work Container - Failed to Send"
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

                for future in concurrent.futures.as_completed(futures):
                    if exitEvent is not None and exitEvent.is_set():
                        break
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
