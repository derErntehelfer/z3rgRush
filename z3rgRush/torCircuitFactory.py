import shutil
import socket
import sys
import tempfile
import time
from contextlib import suppress
from stem.control import Controller
from stem.process import launch_tor_with_config


class torCircuitFactory:
    def __init__(self, numberOfCircuits=3, verbose=False):
        self.verbose = verbose
        self.circuits = []
        self.dataDirs = []

        for currentCircuitNr in range(numberOfCircuits):
            circuitBuildRetries = 3
            self.generateCircuit(currentCircuitNr, circuitBuildRetries)

    def findFreePort(self, host="127.0.0.1"):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((host, 0))
            return sock.getsockname()[1]

    def generateCircuit(self, currentCircuitNr, circuitBuildRetries):
        circuitBuildRetries = circuitBuildRetries
        socksPort = self.findFreePort()
        controlPort = self.findFreePort()
        dataDir = tempfile.mkdtemp()
        self.dataDirs.append(dataDir)

        print(
            f"Circuit {currentCircuitNr}: Ports collected, Temp Data Structures created"
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
            torProcess = launch_tor_with_config(config=torConfig, timeout=30)
        except Exception as e:
            print(
                f"Error starting Tor process for circuit {currentCircuitNr}: {e}",
                file=sys.stderr,
            )
            self.cleanupAll()
            print(
                f"Circuit Factory: Retrying Circuit Generation for Circuit {currentCircuitNr} - {circuitBuildRetries} Retries left",
            )
            if circuitBuildRetries > 0:
                self.cleanupAll()
                self.generateCircuit(currentCircuitNr, (circuitBuildRetries - 1))
            elif circuitBuildRetries == 0:
                print(
                    "Circuit Factory: Max Retries reached, could not build Circuit. Shutting Down"
                )
                self.cleanupAll()
                sys.exit(1)
        print(f"Circuit {currentCircuitNr}: Tor Process launched")

        controller = Controller.from_port(port=controlPort)
        try:
            controller.authenticate()
        except Exception as e:
            print(
                f"Error authenticating controller on port {controlPort}: {e}",
                file=sys.stderr,
            )
            controller.close()
            torProcess.kill()
            self.cleanupSingle(dataDir)
            sys.exit(1)

        print(
            f"Circuit {currentCircuitNr}: Tor Process authenticated, waiting for bootstrap"
        )
        self.waitForBootstrap(controller, currentCircuitNr)
        self.circuits.append((torProcess, controller, socksPort, dataDir))

    def waitForBootstrap(self, controller, currentCircuitNr):
        while True:
            status = controller.get_info("status/bootstrap-phase")
            print(f"Circuit {currentCircuitNr}: {status}")
            if "100" in status:
                break
            time.sleep(1)

    def cleanupSingle(self, dataDir):
        with suppress(Exception):
            shutil.rmtree(dataDir, ignore_errors=True)

    def cleanupAll(self):
        for torProcess, controller, socksPort, dataDir in self.circuits:
            with suppress(Exception):
                controller.close()
            if torProcess is not None:
                try:
                    torProcess.wait(timeout=5)
                except Exception:
                    try:
                        torProcess.kill()
                        torProcess.wait(timeout=1)
                    except Exception:
                        pass
            self.cleanupSingle(dataDir)

    def close(self):
        self.cleanupAll()
