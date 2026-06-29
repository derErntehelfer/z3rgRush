import shutil
import socket
import tempfile
import time
import logging
from contextlib import suppress
from stem.control import Controller
from stem.process import launch_tor_with_config
from rich.progress import Progress, SpinnerColumn, TextColumn
from logger import console

logger = logging.getLogger("z3rgRush.torCircuitFactory")


class torCircuitFactory:
    def __init__(self, numberOfCircuits=3, verbose=False):
        self.verbose = verbose
        self.circuits = []
        self.dataDirs = []

        console.print(f"\nInitializing {numberOfCircuits} Tor circuits...")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,  # <--- FIX 2: Wipes the progress bar cleanly on exit
        ) as progress:
            # Create a single task and reuse it for all circuits
            task = progress.add_task("Starting...", total=None)

            for currentCircuitNr in range(numberOfCircuits):
                progress.update(
                    task,
                    description=f"Building circuit {currentCircuitNr + 1}/{numberOfCircuits}",
                )

                circuitBuildRetries = 3
                self.generateCircuit(
                    currentCircuitNr, circuitBuildRetries, progress, task
                )

        console.print("All circuits initialized successfully\n")

    def findFreePort(self, host="127.0.0.1"):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((host, 0))
            return sock.getsockname()[1]

    def generateCircuit(
        self, currentCircuitNr, circuitBuildRetries, progress=None, task=None
    ):
        if circuitBuildRetries <= 0:
            logger.error(f"Circuit {currentCircuitNr}: Max retries reached")
            raise RuntimeError("Failed to build all circuits after retries")

        socksPort = self.findFreePort()
        controlPort = self.findFreePort()
        dataDir = tempfile.mkdtemp()
        self.dataDirs.append(dataDir)

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
            torProcess = launch_tor_with_config(
                config=torConfig, timeout=30, take_ownership=True
            )
            logger.debug(f"Circuit {currentCircuitNr}: Tor process launched")

            controller = Controller.from_port(port=controlPort)
            controller.authenticate()

            if progress and task:
                progress.update(
                    task,
                    description=f"Circuit {currentCircuitNr + 1}: Bootstrapping...",
                )

            self.waitForBootstrap(controller, currentCircuitNr)
            self.circuits.append((torProcess, controller, socksPort, dataDir))

            if progress and task:
                # Update task to show it's ready
                progress.update(
                    task, description=f"Circuit {currentCircuitNr + 1}: Ready"
                )

            logger.info(f"Circuit {currentCircuitNr} ready (SOCKS: {socksPort})")

        except Exception as e:
            logger.error(f"Circuit {currentCircuitNr}: {e}")
            self.cleanupSingle(dataDir)

            if progress and task:
                progress.update(
                    task,
                    description=f"Circuit {currentCircuitNr + 1}: Retrying...",
                )

            self.generateCircuit(
                currentCircuitNr, circuitBuildRetries - 1, progress, task
            )

    def waitForBootstrap(self, controller, currentCircuitNr):
        while True:
            status = controller.get_info("status/bootstrap-phase")
            logger.debug(f"Circuit {currentCircuitNr}: {status}")

            if "100" in status:
                break
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
