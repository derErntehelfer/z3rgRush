import concurrent.futures
import time
import requests
from stem import Signal


class circuitOvermind:
    def __init__(self, torFactory):
        self.torFactory = torFactory

    def fetchWithCircuit(self, fuzzed, circuitIndex, timeout=10):
        torProcess, controller, socksPort, dataDir = self.torFactory.circuits[
            circuitIndex
        ]

        proxies = {
            "http": f"socks5h://127.0.0.1:{socksPort}",
            "https": f"socks5h://127.0.0.1:{socksPort}",
        }

        controller.signal(Signal.NEWNYM)
        time.sleep(0.5)

        try:
            ipResponse = requests.get(
                "http://httpbin.org/ip", proxies=proxies, timeout=timeout
            )
            exitIp = ipResponse.json().get("origin", "unknown")
        except Exception as ip_error:
            exitIp = f"IP fetch error: {ip_error}"

        try:
            response = requests.get(fuzzed, proxies=proxies, timeout=timeout)
            print(
                f"Circuit {circuitIndex} (port {socksPort}): "
                f"IP={exitIp}, status={response.status_code}, len={len(response.content)} "
                f"-> URL: {fuzzed}"
            )
            return (True, None)
        except Exception as e:
            print(
                f"Circuit {circuitIndex} (port {socksPort}): "
                f"IP={exitIp}, error -> {e} "
                f"(URL: {fuzzed})"
            )
            print(f"Payload {fuzzed} returned to Work Container")
            return (False, fuzzed)

    def sendPayloads(self, payloads, workers=None, timeout=10):
        work = list(payloads)

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(
                    self.fetchWithCircuit,
                    fuzzed,
                    circuitIndex=i % len(self.torFactory.circuits),
                    timeout=timeout,
                )
                for i, fuzzed in enumerate(work)
            ]

            for future in concurrent.futures.as_completed(futures):
                success, failed_payload = future.result()
                if not success and failed_payload:
                    work.append(failed_payload)

            concurrent.futures.wait(futures)
