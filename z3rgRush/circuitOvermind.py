import time
import requests
import subprocess
import random
import threading
from stem import Signal
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.exceptions import ProxyError, ConnectTimeout, ReadTimeout, Timeout


class circuitOvermind:
    def __init__(
        self,
        torFactory,
        headersInfo=None,
        verbose=False,
        returnCodes=200,
        useExitProxies=False,
    ):
        self.torFactory = torFactory
        self.headerIndex = 0
        self.returnCodes = returnCodes
        self.verbose = verbose
        self.useExitProxies = useExitProxies
        self.collectedOutput = []
        self.exitProxyList = self.useExitProxy() if self.useExitProxies else []
        self.badProxies = set()
        self.proxyIndex = 0
        self.stopEvent = threading.Event()

        if headersInfo and headersInfo.get("config"):
            self.headerSets = headersInfo["config"]
            print(
                f"Overmind: Loaded {len(self.headerSets.get('user_agents', []))} UAs from {headersInfo['file']}"
            )
        else:
            self.headerSets = {
                "user_agents": ["Mozilla/5.0 (compatible; z3rgRush/1.0)"],
                "accept_headers": ["*/*"],
                "accept_languages": ["en-US,en;q=0.9"],
                "accept_encodings": ["gzip, deflate"],
                "referers": ["https://www.google.com/"],
                "sec_fetch_dest": ["document"],
                "sec_fetch_mode": ["navigate"],
                "sec_fetch_site": ["none"],
                "sec_ch_ua_mobile": ["?0"],
                "sec_ch_ua_platforms": ['"Windows"'],
            }
            print("No headers config loaded, using minimal defaults")

    def get_next_proxy(self):
        available_proxies = [
            p for p in self.exitProxyList if p["http"] not in self.badProxies
        ]
        if not available_proxies:
            print("Overmind: No working proxies available, refreshing proxy list...")
            self.exitProxyList = self.useExitProxy()
            self.badProxies.clear()
            available_proxies = self.exitProxyList
            if not available_proxies:
                return None

        self.proxyIndex = (self.proxyIndex + 1) % len(available_proxies)
        return available_proxies[self.proxyIndex]

    def mark_proxy_bad(self, proxy_url):
        self.badProxies.add(proxy_url)
        print(
            f"Overmind: Marked proxy as bad: {proxy_url} ({len(self.badProxies)} bad proxies)"
        )

    def get_next_headers(self):
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

    def getExitIp(self, proxies=None, timeout=5, headers=None):
        try:
            if proxies is None:
                ipResponse = requests.get(
                    "http://httpbin.org/ip", timeout=timeout, headers=headers
                )
            else:
                ipResponse = requests.get(
                    "http://httpbin.org/ip",
                    proxies=proxies,
                    timeout=timeout,
                    headers=headers,
                )
            exitIp = ipResponse.json().get("origin", "unknown")
            if "," in exitIp:
                exitIp = exitIp.split(",")[0].strip()
        except Exception as ip_error:
            exitIp = f"IP fetch error: {ip_error}"
        return exitIp

    def useExitProxy(self):
        print("circuitOvermind: Fetching free proxies...")
        curlCmd = [
            "curl",
            "-s",
            "https://api.proxyscrape.com/v4/free-proxy-list/get?protocol=http&timeout=10000&country=all&ssl=all&anonymity=all&limit=2000&request=displayproxies",
        ]
        curlResult = subprocess.run(curlCmd, capture_output=True, text=True, timeout=30)
        rawProxies = []
        for line in curlResult.stdout.splitlines():
            line = line.strip()
            if ":" in line and not line.startswith("#") and len(line.split(":")) == 2:
                rawProxies.append(line)

        print(f"circuitOvermind: proxies collected: {len(rawProxies)}")
        proxyList = []
        for proxyStrings in rawProxies[:2000]:
            try:
                host, portStrings = proxyStrings.split(":", 1)
                port = int(portStrings)
                if 1 <= port <= 65535:
                    proxyDictonary = {
                        "http": f"http://{host}:{port}",
                        "https": f"http://{host}:{port}",
                    }
                    proxyList.append(proxyDictonary)
            except (ValueError, IndexError):
                continue

        random.shuffle(proxyList)
        print(f"Total usable proxies collected: {len(proxyList)}")
        if self.verbose:
            print(f"Sample proxies: {proxyList[:3]}")
        return proxyList

    def fetchWithCircuit(
        self,
        fuzzed,
        circuitIndex,
        method="GET",
        data=None,
        timeout=10,
        customHeaders=None,
        maxProxyRetries=3,
        **kwargs,
    ):
        torProcess, controller, socksPort, dataDir = self.torFactory.circuits[
            circuitIndex
        ]

        if self.useExitProxies and self.exitProxyList:
            exit_proxy = self.get_next_proxy()
            if not exit_proxy:
                print(f"No working exit proxy available for circuit {circuitIndex}")
                proxies = {
                    "http": f"socks5h://127.0.0.1:{socksPort}",
                    "https": f"socks5h://127.0.0.1:{socksPort}",
                }
            else:
                print(
                    f"Using Tor circuit {circuitIndex} -> Exit proxy {exit_proxy['http']}"
                )
                proxies = exit_proxy
        else:
            proxies = {
                "http": f"socks5h://127.0.0.1:{socksPort}",
                "https": f"socks5h://127.0.0.1:{socksPort}",
            }

        controller.signal(Signal.NEWNYM)
        time.sleep(0.5)

        headers = self.get_next_headers()
        if customHeaders:
            headers.update(customHeaders)

        exitIp = self.getExitIp(proxies, timeout=5, headers=headers)

        for proxy_attempt in range(maxProxyRetries):
            try:
                session = requests.Session()
                method_func = getattr(session, method.lower())
                response = method_func(
                    fuzzed,
                    proxies=proxies,
                    headers=headers,
                    timeout=timeout,
                    data=data,
                    **kwargs,
                )

                resultToCollect = (
                    f"Circuit {circuitIndex} ({method}) (port {socksPort}): "
                    f"IP={exitIp}, status={response.status_code}, len={len(response.content)} "
                    f"(URL: {fuzzed})"
                )
                print(resultToCollect)
                self.printHeadersVerbose(headers)

                codesForRetry = {429, 430, 440, 449, 503, 521, 523, 524}
                if response.status_code in codesForRetry:
                    print(
                        f"Overmind: Payload {fuzzed} returned to Work Container - Response Status"
                    )
                    return (False, fuzzed)
                if response.status_code in self.returnCodes:
                    self.collectedOutput.append(resultToCollect)
                return (True, None)

            except (ProxyError, ConnectTimeout, ReadTimeout, Timeout) as proxy_error:
                proxy_url = proxies.get("http", "unknown")
                print(
                    f"Circuit {circuitIndex} proxy attempt {proxy_attempt + 1}/{maxProxyRetries}: {proxy_error}"
                )

                if (
                    self.useExitProxies
                    and proxy_url != f"socks5h://127.0.0.1:{socksPort}"
                ):
                    self.mark_proxy_bad(proxy_url)

                if proxy_attempt < maxProxyRetries - 1:
                    if self.useExitProxies and self.exitProxyList:
                        exit_proxy = self.get_next_proxy()
                        if exit_proxy:
                            proxies = exit_proxy
                            print(f"Retrying with new proxy: {exit_proxy['http']}")
                            time.sleep(0.5)
                            continue
                    time.sleep(1)
                else:
                    print(f"All proxy attempts failed for {fuzzed}")

            except Exception as e:
                print(
                    f"Circuit {circuitIndex} ({method}) (port {socksPort}): IP={exitIp}, error -> {e} (URL: {fuzzed})"
                )
                print(
                    f"Overmind: Payload {fuzzed} returned to Work Container - Failed to Send"
                )
                return (False, fuzzed)

        return (False, fuzzed)

    def sendPayloads(
        self,
        payloads,
        workers=None,
        timeout=10,
        method="GET",
        postData=False,
        customHeaders=None,
        useExitProxies=False,
    ):

        self.useExitProxies = useExitProxies
        self.stopping = False
        self.stopEvent = threading.Event()

        if self.useExitProxies and not self.exitProxyList:
            self.exitProxyList = self.useExitProxy()

        work = list(payloads)

        def shouldStop():
            return self.stopping or self.stopEvent.is_set()

        try:
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = []

                while work and not shouldStop():
                    currentWork = work
                    work = []
                    futures = []

                    for i, payload in enumerate(currentWork):
                        if shouldStop():
                            break
                        circuitIdx = i % len(self.torFactory.circuits)
                        futures.append(
                            executor.submit(
                                self.fetchWithCircuit,
                                payload,
                                circuitIdx,
                                method=method,
                                timeout=timeout,
                                customHeaders=customHeaders,
                                maxProxyRetries=3,
                            )
                        )

                    try:
                        for future in as_completed(futures):
                            if shouldStop():
                                break
                            success, failedPayload = future.result()
                            if not success and failedPayload and not shouldStop():
                                work.append(failedPayload)
                    except KeyboardInterrupt:
                        self.stopping = True
                        self.stopEvent.set()
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
        except KeyboardInterrupt:
            self.stopping = True
            self.stopEvent.set()

    def printCollectedOutput(self):
        print("------ Collected Results ------")
        for outputs in self.collectedOutput:
            print(outputs)
