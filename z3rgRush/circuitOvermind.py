import concurrent.futures
import random
import socket
import sys
import time
import subprocess
import threading
import logging
import requests
from requests.adapters import HTTPAdapter
from stem import Signal

try:
    import socks
except ImportError:
    try:
        import pyChainedProxy as socks

        sys.modules["socks"] = socks
    except ImportError:
        pass

logger = logging.getLogger("z3rgRush.circuitOvermind")


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

        # Shared sessions per circuit with enlarged connection pools
        self.sessions = {}
        adapter = HTTPAdapter(pool_connections=20, pool_maxsize=50)

        for i in range(len(self.torFactory.circuits)):
            session = requests.Session()
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            self.sessions[i] = session

        self.headerIndex = 0
        self.returnCodes = returnCodes
        self.verbose = verbose
        self.collectedOutput = []
        self.useProxyExit = proxySet
        self.hitsFromReturnCode = []
        self.recursion = recursion

        num_circuits = len(self.torFactory.circuits)

        self.circuitIps = {i: "Unknown" for i in range(num_circuits)}
        self.circuitLastRotation = {i: 0 for i in range(num_circuits)}

        self.headerLock = threading.Lock()
        self.codesForRotation = {403, 429, 430, 440, 449, 503, 521, 523, 524, 502, 504}

        if self.useProxyExit:
            self.upstreamProxies = self.collectProxyscrapeProxies()
            self.badProxies = set()
            logger.info(
                f"Overmind: Collected {len(self.upstreamProxies)} upstream proxies"
            )

        if headersInfo and headersInfo.get("config"):
            self.headerSets = headersInfo["config"]
            logger.info(
                f"Overmind: Loaded {len(self.headerSets.get('user_agents', []))} UAs from {headersInfo['file']}"
            )
        else:
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
            logger.info("No headers config loaded, using minimal defaults")

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
                return [f"http://{line}" for line in proxyLines if ":" in line][:50]
        except Exception as e:
            logger.error(f"Proxy collection failed: {e}")
        return []

    def getNextHeaders(self):
        with self.headerLock:
            self.headerIndex += 1
            rotationIndex = self.headerIndex % 100

        headers = {
            "User-Agent": self.headerSets["user_agents"][
                rotationIndex % len(self.headerSets["user_agents"])
            ],
            "Accept": self.headerSets["accept_headers"][
                (rotationIndex + 1) % len(self.headerSets["accept_headers"])
            ],
            "Accept-Language": self.headerSets["accept_languages"][
                (rotationIndex + 2) % len(self.headerSets["accept_languages"])
            ],
            "Accept-Encoding": self.headerSets["accept_encodings"][
                (rotationIndex + 3) % len(self.headerSets["accept_encodings"])
            ],
            "Referer": self.headerSets["referers"][
                (rotationIndex + 4) % len(self.headerSets["referers"])
            ],
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": self.headerSets["sec_fetch_dest"][rotationIndex % 4],
            "Sec-Fetch-Mode": self.headerSets["sec_fetch_mode"][rotationIndex % 4],
            "Sec-Fetch-Site": self.headerSets["sec_fetch_site"][rotationIndex % 4],
            "Sec-Fetch-User": "?1",
            "Sec-CH-UA": '"Chromium";v="129", "Not=A?Brand";v="24", "Google Chrome";v="129"',
            "Sec-CH-UA-Mobile": self.headerSets["sec_ch_ua_mobile"][
                rotationIndex % len(self.headerSets["sec_ch_ua_mobile"])
            ],
            "Sec-CH-UA-Platform": self.headerSets["sec_ch_ua_platforms"][
                rotationIndex % len(self.headerSets["sec_ch_ua_platforms"])
            ],
        }
        return headers

    def printHeadersVerbose(self, headers):
        if not self.verbose:
            return
        logger.debug("  Headers:")
        for key, value in headers.items():
            logger.debug(f"    {key}: {value}")

    def getExitIp(self, proxies, timeout, headers):
        endpoints = [
            ("https://api.ipify.org?format=json", lambda r: r.json().get("ip")),
            ("https://httpbin.org/ip", lambda r: r.json().get("origin")),
            ("https://ifconfig.me/ip", lambda r: r.text.strip()),
        ]
        for url, parser in endpoints:
            try:
                ipResponse = requests.get(
                    url, proxies=proxies, timeout=timeout, headers=headers
                )
                ipResponse.raise_for_status()
                exitIp = parser(ipResponse)
                if exitIp and ", " in exitIp:
                    exitIp = exitIp.split(", ")[0].strip()
                if exitIp:
                    return exitIp
            except Exception:
                continue
        return "IP fetch error"

    def _fetchIpInBackground(self, circuitIndex, proxies, timeout, headers):
        """Fetches the exit IP in a background thread to prevent blocking the main request pipeline."""

        def _fetch():
            ip = self.getExitIp(proxies, timeout, headers)
            self.circuitIps[circuitIndex] = ip

        threading.Thread(target=_fetch, daemon=True).start()

    def rotateCircuit(self, circuitIndex, reason=None):
        current_time = time.time()
        # Prevent rotation storms without holding a lock during the sleep
        if current_time - self.circuitLastRotation[circuitIndex] < 5.0:
            return

        # Mark as rotating immediately to prevent duplicate signals
        self.circuitLastRotation[circuitIndex] = current_time

        torProcess, controller, socksPort, dataDir = self.torFactory.circuits[
            circuitIndex
        ]
        try:
            controller.signal(Signal.NEWNYM)
            # Sleep OUTSIDE of any lock to prevent blocking other threads
            time.sleep(1.5)
            if reason or self.verbose:
                reason_str = f" (Reason: {reason})" if reason else ""
                logger.info(
                    f"Overmind: Circuit {circuitIndex} rotated successfully{reason_str}"
                )
        except Exception as e:
            logger.error(f"Failed to rotate Tor circuit: {e}")

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

        upstreamProxy = None
        exitIp = "Unknown"
        session = self.sessions[circuitIndex]

        try:
            if self.useProxyExit:
                availableProxies = [
                    p for p in self.upstreamProxies if p not in self.badProxies
                ]
                if not availableProxies:
                    logger.warning(
                        "Overmind: All upstream proxies failed - refetching..."
                    )
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

                chain = [f"socks5://127.0.0.1:{socksPort}/", upstreamProxy + "/"]
                chained_socks.setdefaultproxy()
                for hop in chain:
                    chained_socks.adddefaultproxy(*chained_socks.parseproxy(hop))

                original_socket = socket.socket
                socket.socket = chained_socks.socksocket
                try:
                    response = session.request(
                        method=method,
                        url=url,
                        headers=headers,
                        timeout=timeout,
                        data=data,
                        **requestKwargs,
                    )
                finally:
                    socket.socket = original_socket
            else:
                proxies = {
                    "http": f"socks5h://127.0.0.1:{socksPort}",
                    "https": f"socks5h://127.0.0.1:{socksPort}",
                }

                if self.circuitIps[circuitIndex] == "Unknown":
                    self.circuitIps[circuitIndex] = "Fetching..."
                    self._fetchIpInBackground(circuitIndex, proxies, timeout, headers)
                exitIp = self.circuitIps[circuitIndex]

                response = session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    timeout=timeout,
                    data=data,
                    proxies=proxies,
                    **requestKwargs,
                )

            if self.verbose:
                chain_str = (
                    f" --> Proxy({upstreamProxy})"
                    if self.useProxyExit and upstreamProxy
                    else ""
                )
                logger.debug(
                    f"Overmind: [CHAIN] Local --> Tor({socksPort}){chain_str} --> Exit({exitIp}) --> {url}"
                )

            resultToCollect = (
                f"Circuit {circuitIndex} ({method}) (port {socksPort}): "
                f"IP={exitIp}, status={response.status_code}, len={len(response.content)} "
                f"(URL: {url})"
            )
            logger.info(resultToCollect)
            self.printHeadersVerbose(headers)

            if response.status_code in self.returnCodes:
                self.collectedOutput.append(resultToCollect)
                if self.recursion >= 1:
                    self.hitsFromReturnCode.append((url + "/" + "{SWARM}"))
                return (True, None)

            if response.status_code in self.codesForRotation and not exitEvent.is_set():
                logger.warning(
                    f"Overmind: Rate limit/WAF detected (status {response.status_code}) on circuit {circuitIndex} - rotating circuit"
                )
                self.rotateCircuit(
                    circuitIndex, reason=f"WAF/Rate Limit ({response.status_code})"
                )
                logger.info(
                    f"Overmind: Payload {url} returned to Work Container - Response Status {response.status_code}"
                )
                return (False, requestSpec)

            return (True, None)

        except requests.exceptions.Timeout:
            if not exitEvent.is_set():
                if self.useProxyExit and upstreamProxy:
                    self.badProxies.add(upstreamProxy)
                    logger.warning(
                        f"Overmind: [BAD PROXY] {upstreamProxy} timed out - blacklisted"
                    )
                logger.warning(
                    f"Overmind: Payload {url} returned to Work Container - Timed out"
                )
                self.rotateCircuit(circuitIndex, reason="Timeout")
            return (False, requestSpec)

        except requests.exceptions.ConnectionError as ce:
            if "refused" in str(ce).lower() or "reset" in str(ce).lower():
                if not exitEvent.is_set():
                    if self.useProxyExit and upstreamProxy:
                        self.badProxies.add(upstreamProxy)
                        logger.warning(
                            f"Overmind: [BAD PROXY] {upstreamProxy} connection refused/reset - blacklisted"
                        )
                    logger.warning(
                        f"Overmind: Payload {url} returned to Work Container - Connection refused"
                    )
                    self.rotateCircuit(circuitIndex, reason="Connection Refused/Reset")
            return (False, requestSpec)

        except Exception as e:
            if not exitEvent.is_set():
                if self.useProxyExit and upstreamProxy:
                    self.badProxies.add(upstreamProxy)
                    logger.error(
                        f"Overmind: [BAD PROXY] {upstreamProxy} threw error {e} - blacklisted"
                    )
                logger.error(
                    f"Circuit {circuitIndex} ({method}) (port {socksPort}): IP={exitIp}, error -> {e} (URL: {url})"
                )
                logger.warning(
                    f"Overmind: Payload {url} returned to Work Container - Failed to Send"
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

        # Create the executor ONCE to avoid thread-spawning overhead
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            while (
                work
                and maxRetries > 0
                and (exitEvent is None or not exitEvent.is_set())
            ):
                currentWork = work[:]
                work = []
                futures = []

                try:
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
                    logger.error(f"sendPayloads failed: {e}")
                    if exitEvent is not None:
                        exitEvent.set()

        if work and (exitEvent is None or not exitEvent.is_set()):
            logger.warning(f"Failed payloads after {maxRetries} retries: {len(work)}")

    def getHitsForRecursion(self):
        return self.hitsFromReturnCode

    def cleanUrlListInRecursion(self):
        self.hitsFromReturnCode.clear()

    def printCollectedOutput(self):
        logger.info("------ Collected Results ------")
        if self.collectedOutput:
            for outputs in self.collectedOutput:
                logger.info(outputs)
        else:
            logger.info("No Results Collected")
        logger.info("------ Collected Results ------")
