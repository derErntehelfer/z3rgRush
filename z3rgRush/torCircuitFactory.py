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

        console.print(f"\nInitializing {numberOfCircuits} Tor circuits in parallel...")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Building circuits...", total=numberOfCircuits)

            # Build circuits in parallel using ThreadPoolExecutor
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=numberOfCircuits
            ) as executor:
                futures = {
                    executor.submit(self._buildCircuit, i, 3, progress, task): i
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
                    except Exception as e:
                        logger.error(f"Circuit {circuit_idx} failed to build: {e}")

        # Prevent cascade failure if all circuits fail
        if not self.circuits:
            logger.error("Failed to build ANY circuits. Exiting.")
            raise RuntimeError("No circuits could be initialized.")

        console.print(
            f"All circuits initialized successfully ({len(self.circuits)} active)\n"
        )

    def _drainOutput(self, process, circuitNr):
        """Drains stdout to prevent pipe buffer blocking."""
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
        self, currentCircuitNr, circuitBuildRetries, progress=None, task=None
    ):
        if circuitBuildRetries <= 0:
            logger.error(f"Circuit {currentCircuitNr}: Max retries reached")
            return None

        socksPort = self.findFreePort()
        controlPort = self.findFreePort()
        dataDir = tempfile.mkdtemp()

        logger.debug(
            f"Circuit {currentCircuitNr}: Ports {socksPort}/{controlPort}, DataDir: {dataDir}"
        )

        torConfig = {
            "SocksPort": str(socksPort),
            "ControlPort": str(controlPort),
            "DataDirectory": dataDir,
            "CookieAuthentication": "1",
            "ExitPolicy": "reject *:*",
            "CircuitBuildTimeout": "90",
            "Log": ["NOTICE stdout"] if self.verbose else [],
        }

        try:
            tor_cmd = shutil.which("tor") or "tor"
            torrc_path = os.path.join(dataDir, "torrc")

            # Write config manually
            with open(torrc_path, "w") as f:
                for k, v in torConfig.items():
                    if isinstance(v, list):
                        for item in v:
                            f.write(f"{k} {item}\n")
                    else:
                        f.write(f"{k} {v}\n")

            # Launch via subprocess to bypass stem's main-thread timeout restriction
            torProcess = subprocess.Popen(
                [tor_cmd, "-f", torrc_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )

            # Drain stdout in background to prevent blocking
            threading.Thread(
                target=self._drainOutput,
                args=(torProcess, currentCircuitNr),
                daemon=True,
            ).start()

            logger.debug(
                f"Circuit {currentCircuitNr}: Tor process launched via subprocess"
            )

            # Wait for control port to become available
            controller = None
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
            return (torProcess, controller, socksPort, dataDir)

        except Exception as e:
            logger.error(f"Circuit {currentCircuitNr}: {e}")
            self.cleanupSingle(dataDir)

            if progress and task:
                progress.update(
                    task, description=f"Circuit {currentCircuitNr + 1}: Retrying..."
                )

            return self._buildCircuit(
                currentCircuitNr, circuitBuildRetries - 1, progress, task
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
                logger.debug(f"Circuit {currentCircuitNr}: {status}")

                if "100" in status:
                    break
            except Exception as e:
                logger.debug(f"Circuit {currentCircuitNr}: Control port error: {e}")

            time.sleep(1)

    def cleanupSingle(self, dataDir):
        with suppress(Exception):
            shutil.rmtree(dataDir, ignore_errors=True)

    def cleanupAll(self):
        for torProcess, controller, socksPort, dataDir in self.circuits:
            if controller:
                try:
                    controller.close()
                except Exception:
                    pass

            if torProcess is not None:
                try:
                    torProcess.terminate()
                    torProcess.wait(timeout=2)
                except Exception:
                    try:
                        torProcess.kill()
                        torProcess.wait(timeout=1)
                    except Exception:
                        pass
            self.cleanupSingle(dataDir)

    def close(self):
        self.cleanupAll()
