import shutil
import socket
import sys
import tempfile
import time
import logging
from contextlib import suppress
from stem.control import Controller
from stem.process import launch_tor_with_config
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.console import Console

console = Console()
logger = logging.getLogger("z3rgRush.torCircuitFactory")


class torCircuitFactory:
    def __init__(self, numberOfCircuits=3, verbose=False):
        self.verbose = verbose
        self.circuits = []
        self.dataDirs = []

        console.print(
            f"\n[circuit]Initializing {numberOfCircuits} Tor circuits...[/circuit]"
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            for currentCircuitNr in range(numberOfCircuits):
                task = progress.add_task(
                    f"[circuit]Building circuit {currentCircuitNr + 1}/{numberOfCircuits}[/circuit]",
                    total=None,
                )

                circuitBuildRetries = 3
                self.generateCircuit(
                    currentCircuitNr, circuitBuildRetries, progress, task
                )

        console.print(f"[success] All circuits initialized successfully[/success]\n")

    def findFreePort(self, host="127.0.0.1"):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((host, 0))
            return sock.getsockname()[1]

    def generateCircuit(
        self, currentCircuitNr, circuitBuildRetries, progress=None, task=None
    ):
        if circuitBuildRetries <= 0:
            logger.error(
                f"[error]Circuit {currentCircuitNr}: Max retries reached[/error]"
            )
            raise RuntimeError("Failed to build all circuits after retries")

        circuitBuildRetries = circuitBuildRetries
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
            # take_ownership=True ensures Tor dies if Python crashes or is force-killed
            torProcess = launch_tor_with_config(
                config=torConfig, timeout=30, take_ownership=True
            )
            logger.debug(f"Circuit {currentCircuitNr}: Tor process launched")

            controller = Controller.from_port(port=controlPort)
            controller.authenticate()

            if progress and task:
                progress.update(
                    task,
                    description=f"[circuit]Circuit {currentCircuitNr + 1}: Bootstrapping...[/circuit]",
                )

            self.waitForBootstrap(controller, currentCircuitNr)
            self.circuits.append((torProcess, controller, socksPort, dataDir))

            logger.info(
                f"[success]Circuit {currentCircuitNr} ready (SOCKS: {socksPort})[/success]"
            )

        except Exception as e:
            logger.error(f"[error]Circuit {currentCircuitNr}: {e}[/error]")
            self.cleanupSingle(dataDir)

            if progress and task:
                progress.update(
                    task,
                    description=f"[warning]Circuit {currentCircuitNr + 1}: Retrying...[/warning]",
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
            if torProcess is not None:
                try:
                    torProcess.terminate()  # Send SIGTERM for graceful exit
                    torProcess.wait(timeout=2)
                except Exception:
                    try:
                        torProcess.kill()  # Force kill if it ignores SIGTERM
                        torProcess.wait(timeout=1)
                    except Exception:
                        pass
            self.cleanupSingle(dataDir)

    def close(self):
        self.cleanupAll()
