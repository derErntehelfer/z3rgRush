import concurrent.futures
import time
import requests
from stem import Signal


class circuitOvermind:
    def __init__(self, torFactory, headersInfo=None, verbose=False, returnCodes=200):
        self.torFactory = torFactory
        self.headerIndex = 0
        self.returnCodes = returnCodes
        self.verbose = verbose
        self.collectedOutput = []

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

        proxies = {
            "http": f"socks5h://127.0.0.1:{socksPort}",
            "https": f"socks5h://127.0.0.1:{socksPort}",
        }
        codesForRetry = {429, 430, 440, 449, 503, 521, 523, 524}

        controller.signal(Signal.NEWNYM)
        time.sleep(0.5)

        # Merge rotating headers with custom headers
        headers = self.get_next_headers()
        if customHeaders:
            headers.update(customHeaders)

        exitIp = self.getExitIp(proxies, timeout, headers)

        try:
            method_func = getattr(requests, method.lower())
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
            if response.status_code in codesForRetry:
                print(
                    f"Overmind: Payload {fuzzed} returned to Work Container - Response Status"
                )
                return (False, fuzzed)
            if response.status_code in self.returnCodes:
                self.collectedOutput.append(resultToCollect)
            return (True, None)
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
            current_work = work
            work = []  # Reset for next iteration

            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                futures = []
                for i, payload in enumerate(current_work):
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

        if work:
            print(f"Failed payloads after {maxRetries} retries: {len(work)}")

    def printCollectedOutput(self):
        print("------ Collected Results ------")
        for outputs in self.collectedOutput:
            print(outputs)
