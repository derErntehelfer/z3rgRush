# z3rgRush/circuitOvermind.py
import concurrent.futures
import copy
import random
import socket
import sys
import time
import subprocess
import threading
import logging
import requests

from contextlib import suppress
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from stem import Signal

try:
    import socks
except ImportError:
    try:
        import pyChainedProxy as socks

        sys.modules["socks"] = socks
    except ImportError:
        socks = None

logger = logging.getLogger("z3rgRush.circuitOvermind")


DEFAULT_HEADER_SETS = {
    "user_agents": ["Mozilla/5.0 (compatible; z3rgRush/1.0)"],
    "accept_headers": ["*/*"],
    "accept_languages": ["en-US,en;q=0.9"],
    "accept_encodings": ["gzip, deflate"],
    "referers": ["https://www.google.com/"],
    "sec_fetch_dest": ["document"],
    "sec_fetch_mode": ["navigate"],
    "sec_fetch_site": ["same-origin"],
    "sec_ch_ua_mobile": ["?0"],
    "sec_ch_ua_platforms": ['"Windows"'],
}


class circuitExitSidecar:
    """
    Minimal local HTTP proxy sidecar for one Tor circuit.

    requests -> local sidecar -> Tor SOCKS -> upstream proxy -> target

    The upstream proxy is chosen dynamically per connection.
    """

    def __init__(self, circuitIndex, socksPort, overmind):
        self.circuitIndex = circuitIndex
        self.socksPort = socksPort
        self.overmind = overmind

        self.running = False
        self.listener = None
        self.port = None
        self.thread = None

    def start(self):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(128)

        self.port = self.listener.getsockname()[1]
        self.running = True

        self.thread = threading.Thread(target=self._acceptLoop, daemon=True)
        self.thread.start()

        logger.info(
            f"Overmind: Started exit sidecar for circuit {self.circuitIndex} "
            f"on 127.0.0.1:{self.port}"
        )

    def stop(self):
        self.running = False

        if self.listener is not None:
            with suppress(Exception):
                self.listener.close()

    def _acceptLoop(self):
        self.listener.settimeout(0.5)

        while self.running:
            try:
                clientSocket, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            threading.Thread(
                target=self._handleClient,
                args=(clientSocket,),
                daemon=True,
            ).start()

    def _handleClient(self, clientSocket):
        try:
            clientSocket.settimeout(30)

            head, remainder = self._readHead(clientSocket)
            if not head:
                return

            lines = head.split(b"\r\n")
            if not lines:
                return

            requestLine = lines[0].decode("latin-1", "ignore")
            headerLines = lines[1:]

            parts = requestLine.split()
            if len(parts) < 3:
                return

            method = parts[0].upper()
            target = parts[1]

            if method == "CONNECT":
                self._handleConnect(
                    clientSocket=clientSocket,
                    authority=target,
                    headerLines=headerLines,
                    remainder=remainder,
                )
            else:
                self._handleHttp(
                    clientSocket=clientSocket,
                    requestLine=requestLine,
                    headerLines=headerLines,
                    remainder=remainder,
                )

        except Exception as err:
            logger.debug(
                f"Sidecar circuit {self.circuitIndex}: client handler error: {err}"
            )
        finally:
            with suppress(Exception):
                clientSocket.close()

    def _readHead(self, sock):
        data = b""

        try:
            while b"\r\n\r\n" not in data:
                chunk = sock.recv(65536)
                if not chunk:
                    break

                data += chunk

                if len(data) > 1048576:
                    break
        except Exception:
            return None, b""

        if b"\r\n\r\n" not in data:
            return None, b""

        head, remainder = data.split(b"\r\n\r\n", 1)
        return head, remainder

    def _getHeaderValue(self, headerLines, headerName):
        headerName = headerName.lower()

        for line in headerLines:
            if b":" not in line:
                continue

            key, value = line.split(b":", 1)
            key = key.decode("latin-1", "ignore").strip().lower()

            if key == headerName:
                return value.decode("latin-1", "ignore").strip()

        return None

    def _buildHttpHead(self, requestLine, headerLines, targetUrl):
        parsedTarget = urlparse(targetUrl)

        newHeaders = []
        hasHost = False

        for line in headerLines:
            if b":" not in line:
                continue

            key = line.split(b":", 1)[0].decode("latin-1", "ignore").strip().lower()

            if key in ("connection", "proxy-connection"):
                continue

            if key == "host":
                hasHost = True

            newHeaders.append(line)

        if not hasHost and parsedTarget.netloc:
            newHeaders.append(
                f"Host: {parsedTarget.netloc}".encode("latin-1", "ignore")
            )

        newHeaders.append(b"Connection: close")
        newHeaders.append(b"Proxy-Connection: close")

        return (
            requestLine.encode("latin-1", "ignore")
            + b"\r\n"
            + b"\r\n".join(newHeaders)
            + b"\r\n\r\n"
        )

    def _connectViaTor(self, upstreamProxy):
        socksModule = self.overmind.socksModule

        if socksModule is None:
            raise RuntimeError("SOCKS module unavailable")

        if "://" not in upstreamProxy:
            upstreamProxy = f"http://{upstreamProxy}"

        parsedProxy = urlparse(upstreamProxy)

        proxyHost = parsedProxy.hostname
        proxyPort = parsedProxy.port or 80

        if not proxyHost:
            raise ValueError(f"Invalid upstream proxy: {upstreamProxy}")

        upstreamSocket = socksModule.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        upstreamSocket.settimeout(15)

        if parsedProxy.username:
            upstreamSocket.set_proxy(
                socksModule.SOCKS5,
                "127.0.0.1",
                self.socksPort,
                rdns=True,
                username=parsedProxy.username,
                password=parsedProxy.password,
            )
        else:
            upstreamSocket.set_proxy(
                socksModule.SOCKS5,
                "127.0.0.1",
                self.socksPort,
                rdns=True,
            )

        upstreamSocket.connect((proxyHost, proxyPort))
        return upstreamSocket

    def _handleHttp(self, clientSocket, requestLine, headerLines, remainder):
        parts = requestLine.split()
        if len(parts) < 3:
            return

        method, target, version = parts[:3]

        if not target.lower().startswith("http://"):
            host = self._getHeaderValue(headerLines, "Host")
            if not host:
                self._sendHttpError(clientSocket, 400, "Missing Host header")
                return

            target = f"http://{host}{target}"
            requestLine = f"{method} {target} {version}"

        transferEncoding = self._getHeaderValue(headerLines, "Transfer-Encoding")
        if transferEncoding and "chunked" in transferEncoding.lower():
            self._sendHttpError(
                clientSocket,
                400,
                "Chunked request bodies are not supported by this minimal sidecar",
            )
            return

        upstreamProxy = self.overmind.chooseUpstreamProxy()
        if not upstreamProxy:
            self._sendHttpError(clientSocket, 502, "No upstream proxy available")
            return

        try:
            upstreamSocket = self._connectViaTor(upstreamProxy)
        except Exception as err:
            logger.debug(
                f"Sidecar circuit {self.circuitIndex}: "
                f"upstream connect failed for {upstreamProxy}: {err}"
            )
            self.overmind.markBadUpstreamProxy(upstreamProxy)
            self._sendHttpError(clientSocket, 502, "Upstream proxy connect failed")
            return

        try:
            upstreamSocket.settimeout(30)

            contentLengthValue = self._getHeaderValue(headerLines, "Content-Length")
            try:
                contentLength = int(contentLengthValue or 0)
            except Exception:
                contentLength = 0

            headOut = self._buildHttpHead(
                requestLine=requestLine,
                headerLines=headerLines,
                targetUrl=target,
            )

            upstreamSocket.sendall(headOut)

            self._forwardBody(
                clientSocket=clientSocket,
                upstreamSocket=upstreamSocket,
                contentLength=contentLength,
                remainder=remainder,
            )

            self._relay(
                sourceSocket=upstreamSocket,
                destinationSocket=clientSocket,
            )

        except Exception as err:
            logger.debug(
                f"Sidecar circuit {self.circuitIndex}: "
                f"HTTP proxy error for {upstreamProxy}: {err}"
            )
            self.overmind.markBadUpstreamProxy(upstreamProxy)
        finally:
            with suppress(Exception):
                upstreamSocket.close()

    def _handleConnect(self, clientSocket, authority, headerLines, remainder):
        upstreamProxy = self.overmind.chooseUpstreamProxy()

        if not upstreamProxy:
            self._sendHttpError(clientSocket, 502, "No upstream proxy available")
            return

        try:
            upstreamSocket = self._connectViaTor(upstreamProxy)
        except Exception as err:
            logger.debug(
                f"Sidecar circuit {self.circuitIndex}: "
                f"CONNECT upstream connect failed for {upstreamProxy}: {err}"
            )
            self.overmind.markBadUpstreamProxy(upstreamProxy)
            self._sendHttpError(clientSocket, 502, "Upstream proxy connect failed")
            return

        try:
            connectHead = (
                f"CONNECT {authority} HTTP/1.1\r\n"
                f"Host: {authority}\r\n"
                "Proxy-Connection: close\r\n"
                "\r\n"
            ).encode("latin-1", "ignore")

            upstreamSocket.sendall(connectHead)

            responseHead, responseRemainder = self._readHead(upstreamSocket)
            if not responseHead:
                self.overmind.markBadUpstreamProxy(upstreamProxy)
                self._sendHttpError(clientSocket, 502, "Upstream CONNECT failed")
                return

            statusLine = responseHead.split(b"\r\n", 1)[0].decode("latin-1", "ignore")
            statusParts = statusLine.split()

            if len(statusParts) < 2 or not statusParts[1].startswith("2"):
                self.overmind.markBadUpstreamProxy(upstreamProxy)
                self._sendHttpError(
                    clientSocket,
                    502,
                    f"Upstream CONNECT rejected: {statusLine}",
                )
                return

            clientSocket.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

            clientSocket.settimeout(None)
            upstreamSocket.settimeout(None)

            self._tunnel(
                clientSocket=clientSocket,
                upstreamSocket=upstreamSocket,
                initialData=responseRemainder,
            )

        except Exception as err:
            logger.debug(
                f"Sidecar circuit {self.circuitIndex}: "
                f"CONNECT error via {upstreamProxy}: {err}"
            )
            self.overmind.markBadUpstreamProxy(upstreamProxy)
        finally:
            with suppress(Exception):
                upstreamSocket.close()

    def _forwardBody(self, clientSocket, upstreamSocket, contentLength, remainder):
        if contentLength <= 0:
            return

        if remainder:
            chunk = remainder[:contentLength]
            if chunk:
                upstreamSocket.sendall(chunk)
            contentLength -= len(chunk)

        while contentLength > 0:
            chunk = clientSocket.recv(min(65536, contentLength))
            if not chunk:
                break

            upstreamSocket.sendall(chunk)
            contentLength -= len(chunk)

    def _relay(self, sourceSocket, destinationSocket):
        try:
            while True:
                data = sourceSocket.recv(65536)
                if not data:
                    break

                destinationSocket.sendall(data)
        except Exception:
            pass

    def _tunnel(self, clientSocket, upstreamSocket, initialData=b""):
        if initialData:
            try:
                clientSocket.sendall(initialData)
            except Exception:
                return

        clientThread = threading.Thread(
            target=self._pipe,
            args=(clientSocket, upstreamSocket),
            daemon=True,
        )

        upstreamThread = threading.Thread(
            target=self._pipe,
            args=(upstreamSocket, clientSocket),
            daemon=True,
        )

        clientThread.start()
        upstreamThread.start()

        clientThread.join()
        upstreamThread.join()

    def _pipe(self, sourceSocket, destinationSocket):
        try:
            while True:
                data = sourceSocket.recv(65536)
                if not data:
                    break

                destinationSocket.sendall(data)
        except Exception:
            pass
        finally:
            with suppress(Exception):
                destinationSocket.shutdown(socket.SHUT_WR)

    def _sendHttpError(self, clientSocket, statusCode, message):
        reasonMap = {
            400: "Bad Request",
            502: "Bad Gateway",
        }

        reason = reasonMap.get(statusCode, "Error")
        body = f"{message}\n".encode("utf-8", "ignore")

        response = (
            f"HTTP/1.1 {statusCode} {reason}\r\n"
            "Content-Type: text/plain\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("latin-1", "ignore") + body

        with suppress(Exception):
            clientSocket.sendall(response)


class circuitOvermind:
    def __init__(
        self,
        torFactory,
        headersInfo=None,
        verbose=False,
        returnCodes=None,
        proxySet=False,
        payloadFactoryInstance=None,
        recursion=0,
    ):
        self.torFactory = torFactory
        self.payloadFactoryInstance = payloadFactoryInstance

        self.sessions = {}

        num_circuits = len(self.torFactory.circuits)
        if num_circuits <= 0:
            raise RuntimeError("Overmind: No Tor circuits available.")

        pool_size = max(50, num_circuits * 10)
        adapter = HTTPAdapter(
            pool_connections=pool_size,
            pool_maxsize=pool_size,
        )

        for i in range(num_circuits):
            session = requests.Session()
            session.trust_env = False
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            self.sessions[i] = session

        self.headerIndex = 0
        self.verbose = verbose
        self.recursion = recursion

        self.collectedOutput = []
        self.hitsFromReturnCode = []

        self.circuitIps = {i: "Unknown" for i in range(num_circuits)}
        self.circuitLastRotation = {i: 0.0 for i in range(num_circuits)}
        self.circuitCooldownUntil = {i: 0.0 for i in range(num_circuits)}
        self.circuitCounter = 0

        self.counterLock = threading.Lock()
        self.headerLock = threading.Lock()
        self.rotationLock = threading.Lock()
        self.hitsLock = threading.Lock()
        self.outputLock = threading.Lock()
        self.socketPatchLock = threading.Lock()

        try:
            if returnCodes is None:
                self.returnCodes = {200}
            else:
                self.returnCodes = {int(code) for code in returnCodes}
        except Exception as err:
            logger.error(
                f"Overmind: Invalid return codes {returnCodes!r}: {err}. "
                "Falling back to [200]."
            )
            self.returnCodes = {200}

        self.codesForRotation = {
            403,
            429,
            430,
            440,
            449,
            503,
            521,
            523,
            524,
            502,
            504,
        }
        self.useProxyExit = proxySet
        self.proxyExitAvailable = False
        self.chainedSocks = None
        self.upstreamProxies = []
        self.badProxies = set()

        self.proxyLock = threading.Lock()
        self.exitSidecars = {}
        self.socksModule = globals().get("socks")

        if self.useProxyExit:
            if (
                self.socksModule is None
                or not hasattr(self.socksModule, "socksocket")
                or not hasattr(self.socksModule, "SOCKS5")
            ):
                logger.error(
                    "Overmind: PySocks-compatible SOCKS support is unavailable. "
                    "Disabling exit proxy mode."
                )
                self.useProxyExit = False
            else:
                self.proxyExitAvailable = True

        if self.useProxyExit and self.proxyExitAvailable:
            self.upstreamProxies = self.collectProxyscrapeProxies()

            logger.info(
                f"Overmind: Collected {len(self.upstreamProxies)} upstream proxies"
            )

            if not self.upstreamProxies:
                logger.warning(
                    "Overmind: No upstream proxies collected. "
                    "Exit proxy mode will fall back to Tor-only as needed."
                )

            for i in range(num_circuits):
                try:
                    _, _, socksPort, _ = self.torFactory.circuits[i]

                    sidecar = circuitExitSidecar(
                        circuitIndex=i,
                        socksPort=socksPort,
                        overmind=self,
                    )

                    sidecar.start()
                    self.exitSidecars[i] = sidecar

                except Exception as err:
                    logger.error(
                        f"Overmind: Failed to start exit sidecar for circuit {i}: {err}"
                    )

        self.headerSets = self.normalizeHeaderSets(headersInfo)

        if headersInfo and headersInfo.get("config"):
            logger.info(
                "Overmind: Loaded "
                f"{len(self.headerSets.get('user_agents', []))} UAs from "
                f"{headersInfo.get('file') or 'memory'}"
            )
        else:
            logger.info("No headers config loaded, using safe internal defaults")

    def normalizeHeaderSets(self, headersInfo):
        config = (headersInfo or {}).get("config") or {}
        normalized = copy.deepcopy(DEFAULT_HEADER_SETS)

        if isinstance(config, dict):
            for key, value in config.items():
                if isinstance(value, list) and value:
                    normalized[key] = [str(item) for item in value]
                elif isinstance(value, str) and value:
                    normalized[key] = [value]

        for key in DEFAULT_HEADER_SETS:
            if not normalized.get(key):
                normalized[key] = DEFAULT_HEADER_SETS[key]

        return normalized

    def pickHeader(self, key, rotationIndex, offset=0):
        values = self.headerSets.get(key)

        if not values:
            return ""

        return values[(rotationIndex + offset) % len(values)]

    def collectProxyscrapeProxies(self):
        curlCmd = [
            "curl",
            "-s",
            "https://api.proxyscrape.com/v4/free-proxy-list/get?protocol=http&timeout=10000&country=all&ssl=all&anonymity=all&limit=2000&request=displayproxies",
        ]

        try:
            result = subprocess.run(
                curlCmd,
                capture_output=True,
                text=True,
                timeout=15,
            )

            if result.returncode == 0:
                proxyLines = []

                for line in result.stdout.splitlines():
                    line = line.strip()

                    if not line:
                        continue

                    if line.startswith("#"):
                        continue

                    if "://" in line:
                        line = line.split("://", 1)[1]

                    line = line.strip("/")

                    if ":" in line:
                        proxyLines.append(line)

                return [f"http://{line}" for line in proxyLines][:50]

        except Exception as err:
            logger.error(f"Proxy collection failed: {err}")

        return []

    def chooseUpstreamProxy(self):
        with self.proxyLock:
            availableProxies = [
                proxy for proxy in self.upstreamProxies if proxy not in self.badProxies
            ]

            if not availableProxies:
                logger.warning("Overmind: All upstream proxies failed - refetching...")

                self.upstreamProxies = self.collectProxyscrapeProxies()
                self.badProxies.clear()

                availableProxies = [
                    proxy
                    for proxy in self.upstreamProxies
                    if proxy not in self.badProxies
                ]

            if not availableProxies:
                return None

            return random.choice(availableProxies)

    def markBadUpstreamProxy(self, upstreamProxy):
        if not upstreamProxy:
            return

        with self.proxyLock:
            if upstreamProxy not in self.badProxies:
                self.badProxies.add(upstreamProxy)
                logger.warning(
                    f"Overmind: [BAD PROXY] {upstreamProxy} marked bad by sidecar"
                )

    def closeSidecars(self):
        for sidecar in list(self.exitSidecars.values()):
            try:
                sidecar.stop()
            except Exception as err:
                logger.debug(f"Overmind: Failed stopping sidecar: {err}")

        self.exitSidecars.clear()

    def getNextHeaders(self):
        with self.headerLock:
            self.headerIndex += 1
            rotationIndex = self.headerIndex % 100

        headers = {
            "User-Agent": self.pickHeader("user_agents", rotationIndex, 0),
            "Accept": self.pickHeader("accept_headers", rotationIndex, 1),
            "Accept-Language": self.pickHeader("accept_languages", rotationIndex, 2),
            "Accept-Encoding": self.pickHeader("accept_encodings", rotationIndex, 3),
            "Referer": self.pickHeader("referers", rotationIndex, 4),
            "Connection": "close",
        }

        return headers, rotationIndex

    def printHeadersVerbose(self, headers):
        if not self.verbose:
            return

        logger.debug("  Headers:")

        for key, value in headers.items():
            logger.debug(f"    {key}: {value}")

    def isExited(self, exitEvent):
        return exitEvent is not None and exitEvent.is_set()

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

                if isinstance(exitIp, list):
                    exitIp = exitIp[0] if exitIp else None

                if exitIp is None:
                    continue

                exitIp = str(exitIp).strip()

                if ", " in exitIp:
                    exitIp = exitIp.split(", ")[0].strip()

                if exitIp:
                    return exitIp

            except Exception:
                continue

        return "IP fetch error"

    def _fetchIpInBackground(self, circuitIndex, proxies, timeout, headers):
        def _fetch():
            try:
                ip = self.getExitIp(proxies, timeout, headers)
                self.circuitIps[circuitIndex] = ip
            except Exception as err:
                logger.debug(f"Background IP fetch failed: {err}")
                self.circuitIps[circuitIndex] = "IP fetch error"

        threading.Thread(target=_fetch, daemon=True).start()

    def rotateCircuit(self, circuitIndex, reason=None):
        with self.rotationLock:
            if circuitIndex not in self.circuitLastRotation:
                return

            now = time.time()

            if now - self.circuitLastRotation[circuitIndex] < 10.0:
                return

            self.circuitLastRotation[circuitIndex] = now
            self.circuitCooldownUntil[circuitIndex] = now + 15.0
            self.circuitIps[circuitIndex] = "Unknown"

        def doRotation():
            try:
                torProcess, controller, socksPort, dataDir = self.torFactory.circuits[
                    circuitIndex
                ]

                controller.signal(Signal.NEWNYM)

                if reason or self.verbose:
                    logger.info(
                        f"Overmind: Circuit {circuitIndex} rotation initiated: {reason}"
                    )

            except Exception as err:
                logger.error(f"Failed to rotate Tor circuit: {err}")

        threading.Thread(target=doRotation, daemon=True).start()

    def getAvailableCircuit(self):
        current_time = time.time()

        available_circuits = [
            idx
            for idx, cooldown_time in self.circuitCooldownUntil.items()
            if current_time >= cooldown_time
        ]

        if not available_circuits:
            return min(
                self.circuitCooldownUntil,
                key=self.circuitCooldownUntil.get,
            )

        with self.counterLock:
            idx = self.circuitCounter % len(available_circuits)
            self.circuitCounter += 1
            return available_circuits[idx]

    def addRecursionHit(self, url):
        if self.recursion < 1:
            return

        baseUrl = url.split("?", 1)[0]
        baseUrl = baseUrl.split("#", 1)[0]
        baseUrl = baseUrl.rstrip("/")

        hit = baseUrl + "/{SWARM}"

        with self.hitsLock:
            if hit not in self.hitsFromReturnCode:
                self.hitsFromReturnCode.append(hit)

    def getHitsForRecursion(self):
        with self.hitsLock:
            return list(self.hitsFromReturnCode)

    def cleanUrlListInRecursion(self):
        with self.hitsLock:
            self.hitsFromReturnCode.clear()

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
        if self.isExited(exitEvent):
            return False, requestSpec

        if not isinstance(requestSpec, dict):
            requestSpec = {
                "url": str(requestSpec),
                "method": "GET",
            }

        try:
            torProcess, controller, socksPort, dataDir = self.torFactory.circuits[
                circuitIndex
            ]
        except Exception as err:
            logger.error(f"Overmind: Invalid circuit index {circuitIndex}: {err}")
            return False, requestSpec

        url = requestSpec.get("url")
        method = str(requestSpec.get("method", "GET"))

        if not url:
            logger.error(f"Overmind: Missing URL in request spec: {requestSpec!r}")
            return False, requestSpec

        headers, rotationIndex = self.getNextHeaders()

        if method.upper() in ["GET", "HEAD", "OPTIONS"]:
            headers.update(
                {
                    "Upgrade-Insecure-Requests": "1",
                    "Sec-Fetch-Dest": self.pickHeader(
                        "sec_fetch_dest",
                        rotationIndex,
                        0,
                    ),
                    "Sec-Fetch-Mode": self.pickHeader(
                        "sec_fetch_mode",
                        rotationIndex,
                        0,
                    ),
                    "Sec-Fetch-Site": self.pickHeader(
                        "sec_fetch_site",
                        rotationIndex,
                        0,
                    ),
                    "Sec-Fetch-User": "?1",
                    "Sec-CH-UA": '"Chromium";v="129", "Not=A?Brand";v="24", "Google Chrome";v="129"',
                    "Sec-CH-UA-Mobile": self.pickHeader(
                        "sec_ch_ua_mobile",
                        rotationIndex,
                        0,
                    ),
                    "Sec-CH-UA-Platform": self.pickHeader(
                        "sec_ch_ua_platforms",
                        rotationIndex,
                        0,
                    ),
                }
            )

        requestData = requestSpec.get("data")
        requestJson = requestSpec.get("json")
        contentType = requestSpec.get("contentType")

        if contentType:
            headers["Content-Type"] = contentType

        if customHeaders:
            headers.update(customHeaders)

        upstreamProxy = None
        exitIp = "Unknown"
        response = None

        session = self.sessions.get(circuitIndex)

        if session is None:
            session = requests.Session()
            session.trust_env = False
            self.sessions[circuitIndex] = session

        try:
            requestKwargs = {
                "method": method,
                "url": url,
                "headers": headers,
                "timeout": timeout,
            }

            if requestJson is not None:
                requestKwargs["json"] = requestJson
            elif requestData is not None:
                requestKwargs["data"] = requestData

            if (
                self.useProxyExit
                and self.proxyExitAvailable
                and circuitIndex in self.exitSidecars
                and self.upstreamProxies
            ):
                sidecar = self.exitSidecars[circuitIndex]
                sidecarUrl = f"http://127.0.0.1:{sidecar.port}"

                proxies = {
                    "http": sidecarUrl,
                    "https": sidecarUrl,
                }

                exitIp = f"Tor+Sidecar(127.0.0.1:{sidecar.port})"

                response = session.request(
                    **requestKwargs,
                    proxies=proxies,
                )

            if response is None:
                if self.useProxyExit and self.proxyExitAvailable:
                    logger.warning(
                        "Overmind: No usable upstream proxies available. "
                        "Falling back to Tor-only for this request."
                    )

            if response is None:
                proxies = {
                    "http": f"socks5h://127.0.0.1:{socksPort}",
                    "https": f"socks5h://127.0.0.1:{socksPort}",
                }

                if self.circuitIps.get(circuitIndex, "Unknown") == "Unknown":
                    self.circuitIps[circuitIndex] = "Fetching..."
                    self._fetchIpInBackground(
                        circuitIndex,
                        proxies,
                        timeout,
                        headers,
                    )

                exitIp = self.circuitIps.get(circuitIndex, "Unknown")
                response = session.request(**requestKwargs, proxies=proxies)

            if self.verbose:
                chain_str = (
                    f" --> Proxy({upstreamProxy})"
                    if self.useProxyExit and upstreamProxy
                    else ""
                )

                logger.debug(
                    f"Overmind: [CHAIN] Local --> Tor({socksPort}){chain_str} "
                    f"--> Exit({exitIp}) --> {url}"
                )

            resultToCollect = (
                f"Circuit {circuitIndex} ({method}) (port {socksPort}): "
                f"IP={exitIp}, status={response.status_code}, "
                f"len={len(response.content or b'')} (URL: {url})"
            )

            logger.info(resultToCollect)
            self.printHeadersVerbose(headers)

            if response.status_code in self.returnCodes:
                with self.outputLock:
                    self.collectedOutput.append(resultToCollect)

                self.addRecursionHit(url)
                return True, None

            if response.status_code in self.codesForRotation and not self.isExited(
                exitEvent
            ):
                logger.warning(
                    "Overmind: Rate limit/WAF detected "
                    f"(status {response.status_code}) on circuit {circuitIndex} "
                    "- rotating circuit"
                )

                self.rotateCircuit(
                    circuitIndex,
                    reason=f"WAF/Rate Limit ({response.status_code})",
                )

                logger.info(
                    f"Overmind: Payload {url} returned to Work Container - "
                    f"Response Status {response.status_code}"
                )

                return False, requestSpec

            return True, None

        except requests.exceptions.Timeout:
            if not self.isExited(exitEvent):
                if self.useProxyExit and upstreamProxy:
                    self.badProxies.add(upstreamProxy)
                    logger.warning(
                        f"Overmind: [BAD PROXY] {upstreamProxy} timed out - blacklisted"
                    )

                logger.warning(
                    f"Overmind: Payload {url} returned to Work Container - Timed out"
                )

                self.rotateCircuit(circuitIndex, reason="Timeout")

            return False, requestSpec

        except requests.exceptions.ConnectionError as err:
            if not self.isExited(exitEvent):
                if self.useProxyExit and upstreamProxy:
                    self.badProxies.add(upstreamProxy)
                    logger.warning(
                        f"Overmind: [BAD PROXY] {upstreamProxy} connection error - blacklisted"
                    )

                logger.warning(
                    f"Overmind: Payload {url} returned to Work Container - "
                    f"Connection error: {err}"
                )

                self.rotateCircuit(
                    circuitIndex,
                    reason="Connection error",
                )

            return False, requestSpec

        except requests.exceptions.RequestException as err:
            if not self.isExited(exitEvent):
                if self.useProxyExit and upstreamProxy:
                    self.badProxies.add(upstreamProxy)
                    logger.warning(
                        f"Overmind: [BAD PROXY] {upstreamProxy} request error - blacklisted"
                    )

                logger.error(
                    f"Circuit {circuitIndex} ({method}) (port {socksPort}): "
                    f"IP={exitIp}, request error -> {err} (URL: {url})"
                )

                self.rotateCircuit(
                    circuitIndex,
                    reason="RequestException",
                )

            return False, requestSpec

        except Exception as err:
            if not self.isExited(exitEvent):
                if self.useProxyExit and upstreamProxy:
                    self.badProxies.add(upstreamProxy)
                    logger.error(
                        f"Overmind: [BAD PROXY] {upstreamProxy} threw error {err} - blacklisted"
                    )

                logger.error(
                    f"Circuit {circuitIndex} ({method}) (port {socksPort}): "
                    f"IP={exitIp}, unexpected error -> {err} (URL: {url})"
                )

                logger.warning(
                    f"Overmind: Payload {url} returned to Work Container - Failed to Send"
                )

                self.rotateCircuit(
                    circuitIndex,
                    reason=f"Exception ({type(err).__name__})",
                )

            return False, requestSpec

    def sendPayloads(
        self,
        payloads,
        workers=None,
        timeout=10,
        postData=False,
        customHeaders=None,
        exitEvent=None,
    ):
        if self.isExited(exitEvent):
            return

        try:
            workers = max(1, int(workers or 1))
        except Exception:
            workers = 1

        try:
            work = list(payloads)
        except Exception as err:
            logger.error(f"Overmind: Failed to materialize payloads: {err}")
            return

        maxRetries = 3

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                while work and maxRetries > 0 and not self.isExited(exitEvent):
                    currentWork = work[:]
                    work = []

                    futureMap = {}

                    for payload in currentWork:
                        if self.isExited(exitEvent):
                            break

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
                                "json": None,
                                "method": "GET",
                                "payload": payload,
                            }

                        circuitIndex = self.getAvailableCircuit()

                        future = executor.submit(
                            self.fetchWithCircuit,
                            requestSpec,
                            circuitIndex,
                            timeout=timeout,
                            customHeaders=customHeaders,
                            exitEvent=exitEvent,
                        )

                        futureMap[future] = requestSpec

                    pending = set(futureMap.keys())

                    while pending:
                        if self.isExited(exitEvent):
                            for future in pending:
                                future.cancel()
                            break

                        done, pending = concurrent.futures.wait(
                            pending,
                            timeout=0.5,
                            return_when=concurrent.futures.FIRST_COMPLETED,
                        )

                        for future in done:
                            requestSpec = futureMap.get(future)

                            try:
                                result = future.result()
                            except Exception as err:
                                logger.error(
                                    "Overmind: Worker crashed for "
                                    f"{requestSpec.get('url') if isinstance(requestSpec, dict) else requestSpec}: {err}"
                                )
                                result = (False, requestSpec)

                            if result is None:
                                result = (False, requestSpec)

                            try:
                                success, failedPayload = result
                            except Exception:
                                success = False
                                failedPayload = requestSpec

                            if (
                                not success
                                and failedPayload
                                and not self.isExited(exitEvent)
                            ):
                                work.append(failedPayload)

                    maxRetries -= 1

                if work and not self.isExited(exitEvent):
                    logger.warning(
                        f"Failed payloads after {maxRetries} retries: {len(work)}"
                    )

        except KeyboardInterrupt:
            logger.warning("Overmind: Interrupt received in sendPayloads.")
            if exitEvent is not None:
                exitEvent.set()

        except Exception as err:
            logger.error(f"sendPayloads failed: {err}")
            if exitEvent is not None:
                exitEvent.set()

    def printCollectedOutput(self):
        logger.info("------ Collected Results ------")

        with self.outputLock:
            if self.collectedOutput:
                for output in self.collectedOutput:
                    logger.info(output)
            else:
                logger.info("No Results Collected")

        logger.info("------ Collected Results ------")
