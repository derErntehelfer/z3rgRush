import concurrent.futures
import random
import socket
import time
import builtins
import subprocess
import pyChainedProxy as socks
import requests
from stem import Signal


def quietPrint(*args, **kwargs):
    # Convert args to string FIRST (no recursion)
    msg = " ".join(str(arg) for arg in args)
    if "Python 3" not in msg:
        # Call ORIGINAL print (saved before patch)
        builtins._original_print(*args, **kwargs)


class circuitOvermind:
    def __init__(
        self,
        torFactory,
        headersInfo=None,
        verbose=False,
        returnCodes=200,
        proxySet=False,
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
                return proxies[:50]  # Limit to 50 fast ones
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
        fuzzed,
        circuitIndex,
        method="GET",
        data=None,
        timeout=10,
        customHeaders=None,
        **kwargs,
    ):
        torProcess, controller, socksPort, dataDir = self.torFactory.circuits[
            circuitIndex
        ]

        controller.signal(Signal.NEWNYM)
        time.sleep(0.5)
        codesForRetry = {429, 430, 440, 449, 503, 521, 523, 524}

        headers = self.getNextHeaders()
        if customHeaders:
            headers.update(customHeaders)

        if self.useProxyExit:
            availableProxies = [
                p for p in self.upstreamProxies if p not in self.badProxies
            ]
            if not availableProxies:
                print("All upstream proxies failed - refetching...")
                self.upstreamProxies = self.collectProxyscrapeProxies()
                self.badProxies.clear()
                availableProxies = self.upstreamProxies
            upstreamProxy = random.choice(availableProxies)
            # Parse upstream proxy (ip:port -> host, port)
            if "://" in upstreamProxy:
                parsed = upstreamProxy.split("://")[1]
            else:
                parsed = upstreamProxy
            host, port = parsed.rsplit(":", 1)
            port = int(port)

            chain = [
                f"socks5://127.0.0.1:{socksPort}/",  # 1st hop: This circuit's Tor
                upstreamProxy + "/",  # 2nd hop: Random upstream HTTP
            ]
        else:
            chain = [
                f"socks5://127.0.0.1:{socksPort}/",  # 1st hop: This circuit's Tor
            ]
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
                method, fuzzed, headers=headers, timeout=timeout, data=data, **kwargs
            )

            if self.verbose and self.useProxyExit:
                print(
                    f"Overmind: [CHAIN] Local --> Tor({socksPort}) --> Proxy({upstreamProxy}) --> Exit({exitIp}) --> {fuzzed}"
                )
            elif self.verbose:
                print(
                    f"Overmind: [CHAIN] Local --> Tor({socksPort}) --> Exit({exitIp}) --> {fuzzed}"
                )
            resultToCollect = (
                f"Circuit {circuitIndex} ({method}) (port {socksPort}): "
                f"IP={exitIp}, status={response.status_code}, len={len(response.content)} "
                f"(URL: {fuzzed})"
            )
            print(resultToCollect)
            self.printHeadersVerbose(headers)
            if response.status_code in codesForRetry:
                print(
                    f"Overmind: Payload {fuzzed} returned to Work Container - Response Status"
                )
                return (False, fuzzed)
            if response.status_code in self.returnCodes:
                self.collectedOutput.append(resultToCollect)
            return (True, None)
        except requests.exceptions.Timeout:
            self.badProxies.add(upstreamProxy)
            print(f"[BAD PROXY] {upstreamProxy} timed out - blacklisted")
            return False, fuzzed
        except requests.exceptions.ConnectionError as ce:
            if "refused" in str(ce).lower() or "reset" in str(ce).lower():
                self.badProxies.add(upstreamProxy)
                print(
                    f"[BAD PROXY] {upstreamProxy} connection refused/reset - blacklisted"
                )
            return False, fuzzed
        except Exception as e:
            print(
                f"Circuit {circuitIndex} ({method}) (port {socksPort}): "
                f"IP={exitIp}, error -> {e} "
                f"(URL: {fuzzed})"
            )
            print(
                f"Overmind: Payload {fuzzed} returned to Work Container - Failed to Send"
            )
            return (False, fuzzed)

    def sendPayloads(
        self,
        payloads,
        workers=None,
        timeout=10,
        method="GET",
        postData=False,
        customHeaders=None,
    ):
        work = list(payloads)
        maxRetries = 3  # Add retry limit

        while work and maxRetries > 0:
            currentWork = work
            work = []  # Reset for next iteration
            originalPrint = getattr(builtins, "_original_print", None)
            if originalPrint is None:
                builtins._original_print = builtins.print
                builtins.print = lambda *args, **kwargs: (
                    None
                    if "Python 3" in " ".join(map(str, args))
                    else builtins._original_print(*args, **kwargs)
                )
            try:
                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=workers
                ) as executor:
                    futures = []
                    for i, payload in enumerate(currentWork):
                        if postData and isinstance(payload, tuple):
                            url, postDataValue = payload
                            futures.append(
                                executor.submit(
                                    self.fetchWithCircuit,
                                    url,
                                    i % len(self.torFactory.circuits),
                                    method=method,
                                    data=postDataValue,
                                    timeout=timeout,
                                    customHeaders=customHeaders,
                                )
                            )
                        else:
                            futures.append(
                                executor.submit(
                                    self.fetchWithCircuit,
                                    payload,
                                    i % len(self.torFactory.circuits),
                                    method=method,
                                    timeout=timeout,
                                    customHeaders=customHeaders,
                                )
                            )

                    for future in concurrent.futures.as_completed(futures):
                        success, failedPayload = future.result()
                        if not success and failedPayload:
                            work.append(failedPayload)
                maxRetries -= 1
            except KeyboardInterrupt:
                print("\nCtrl+C received, shutting down Tor circuits...")
        if work:
            print(f"Failed payloads after {maxRetries} retries: {len(work)}")

    def printCollectedOutput(self):
        print("------ Collected Results ------")
        for outputs in self.collectedOutput:
            print(outputs)
