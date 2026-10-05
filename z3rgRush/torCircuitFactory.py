# /z3rgRush/torCircuitFactory.py
import shutil
import socket
import tempfile
import time
import logging
import os
import subprocess
import threading
import concurrent.futures

from contextlib import suppress

from stem.control import Controller
from rich.progress import Progress, SpinnerColumn, TextColumn

from logger import console

logger = logging.getLogger("z3rgRush.torCircuitFactory")


class torCircuitFactory:
    def __init__(self, numberOfCircuits=3, verbose=False):
        self.verbose = verbose
        self.circuits = []
        self.dataDirs = []

        try:
            numberOfCircuits = max(1, int(numberOfCircuits))
        except Exception:
            numberOfCircuits = 1

        torBinary = shutil.which("tor")

        if torBinary is None:
            raise RuntimeError("Tor binary not found in PATH")

        self.torBinary = torBinary

        console.print(f"\nInitializing {numberOfCircuits} Tor circuits in parallel...")

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task(
                    "Building circuits...",
                    total=numberOfCircuits,
                )

                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=numberOfCircuits
                ) as executor:
                    futures = {
                        executor.submit(
                            self._buildCircuit,
                            i,
                            3,
                            progress,
                            task,
                        ): i
                        for i in range(numberOfCircuits)
                    }

                    for future in concurrent.futures.as_completed(futures):
                        circuit_idx = futures[future]

                        try:
                            result = future.result()

                            if result:
                                torProcess, controller, socksPort, dataDir = result

                                self.circuits.append(
                                    (torProcess, controller, socksPort, dataDir)
                                )

                                self.dataDirs.append(dataDir)

                        except Exception as err:
                            logger.error(
                                f"Circuit {circuit_idx} failed to build: {err}"
                            )

            if not self.circuits:
                logger.error("Failed to build ANY circuits. Exiting.")
                raise RuntimeError("No circuits could be initialized.")

            console.print(
                f"All circuits initialized successfully ({len(self.circuits)} active)\n"
            )

        except BaseException:
            self.cleanupAll()
            raise

    def _drainOutput(self, process, circuitNr):
        try:
            for line in iter(process.stdout.readline, b""):
                if not line:
                    break

                decoded = line.decode("utf-8", errors="replace").strip()

                if decoded and self.verbose:
                    logger.debug(f"Tor[{circuitNr}]: {decoded}")

        except Exception:
            pass

    def _buildCircuit(
        self,
        currentCircuitNr,
        circuitBuildRetries,
        progress=None,
        task=None,
    ):
        if circuitBuildRetries <= 0:
            logger.error(f"Circuit {currentCircuitNr}: Max retries reached")
            return None

        dataDir = None
        torProcess = None
        controller = None

        try:
            socksPort = self.findFreePort()
            controlPort = self.findFreePort()
            dataDir = tempfile.mkdtemp()

            logger.debug(
                f"Circuit {currentCircuitNr}: "
                f"Ports {socksPort}/{controlPort}, DataDir: {dataDir}"
            )

            torConfig = {
                "SocksPort": str(socksPort),
                "ControlPort": str(controlPort),
                "DataDirectory": dataDir,
                "CookieAuthentication": "1",
                "ExitPolicy": "reject *:*",
                "ORPort": "0",
                "DirPort": "0",
                "CircuitBuildTimeout": "90",
                "Log": ["NOTICE stdout"] if self.verbose else [],
            }

            torrc_path = os.path.join(dataDir, "torrc")

            with open(torrc_path, "w") as f:
                for key, value in torConfig.items():
                    if isinstance(value, list):
                        for item in value:
                            f.write(f"{key} {item}\n")
                    else:
                        f.write(f"{key} {value}\n")

            torProcess = subprocess.Popen(
                [self.torBinary, "-f", torrc_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )

            threading.Thread(
                target=self._drainOutput,
                args=(torProcess, currentCircuitNr),
                daemon=True,
            ).start()

            logger.debug(
                f"Circuit {currentCircuitNr}: Tor process launched via subprocess"
            )

            for _ in range(30):
                try:
                    controller = Controller.from_port(port=controlPort)
                    controller.authenticate()
                    break
                except Exception:
                    time.sleep(1)

            if not controller:
                raise RuntimeError("Could not connect to Tor control port")

            if progress and task:
                progress.update(
                    task,
                    description=f"Circuit {currentCircuitNr + 1}: Bootstrapping...",
                )

            self.waitForBootstrap(controller, currentCircuitNr)

            if progress and task:
                progress.update(
                    task,
                    description=f"Circuit {currentCircuitNr + 1}: Ready",
                    advance=1,
                )

            logger.info(f"Circuit {currentCircuitNr} ready (SOCKS: {socksPort})")

            return torProcess, controller, socksPort, dataDir

        except Exception as err:
            logger.error(f"Circuit {currentCircuitNr}: {err}")

            if controller:
                with suppress(Exception):
                    controller.close()

            if torProcess is not None:
                with suppress(Exception):
                    torProcess.terminate()
                    torProcess.wait(timeout=2)

                with suppress(Exception):
                    torProcess.kill()
                    torProcess.wait(timeout=1)

            if dataDir:
                self.cleanupSingle(dataDir)

            if progress and task:
                progress.update(
                    task,
                    description=f"Circuit {currentCircuitNr + 1}: Retrying...",
                )

            return self._buildCircuit(
                currentCircuitNr,
                circuitBuildRetries - 1,
                progress,
                task,
            )

    def findFreePort(self, host="127.0.0.1"):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((host, 0))
            return sock.getsockname()[1]

    def waitForBootstrap(self, controller, currentCircuitNr):
        start_time = time.time()

        while True:
            if time.time() - start_time > 60:
                raise RuntimeError("Bootstrap timed out after 60 seconds")

            try:
                status = controller.get_info("status/bootstrap-phase")
                status = str(status)

                logger.debug(f"Circuit {currentCircuitNr}: {status}")

                if "100" in status:
                    break

            except Exception as err:
                logger.debug(f"Circuit {currentCircuitNr}: Control port error: {err}")

            time.sleep(1)

    def cleanupSingle(self, dataDir):
        with suppress(Exception):
            shutil.rmtree(dataDir, ignore_errors=True)

    def cleanupAll(self):
        for torProcess, controller, socksPort, dataDir in self.circuits:
            if controller:
                with suppress(Exception):
                    controller.close()

            if torProcess is not None:
                with suppress(Exception):
                    torProcess.terminate()
                    torProcess.wait(timeout=2)

                with suppress(Exception):
                    torProcess.kill()
                    torProcess.wait(timeout=1)

            self.cleanupSingle(dataDir)

        self.circuits = []
        self.dataDirs = []

    def close(self):
        self.cleanupAll()
