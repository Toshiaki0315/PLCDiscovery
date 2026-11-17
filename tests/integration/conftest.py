"""
Integration Test Fixtures

Provides fixtures for starting/stopping PLC simulators for integration testing.
"""

import asyncio
import os
import socket
import sys
import time
from multiprocessing import Process
from typing import Generator, Optional
import pytest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


def is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """Check if a port is open and accepting connections"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def wait_for_port(host: str, port: int, timeout: float = 10.0) -> bool:
    """Wait for a port to become available"""
    start_time = time.time()
    while time.time() - start_time < timeout:
        if is_port_open(host, port):
            return True
        time.sleep(0.1)
    return False


class SimulatorProcess:
    """Wrapper for simulator process management"""
    
    def __init__(self, name: str, port: int, start_func):
        self.name = name
        self.port = port
        self.start_func = start_func
        self.process: Optional[Process] = None
    
    def start(self):
        """Start the simulator process"""
        if self.is_running():
            return
        # Another process (typically simulators/run_all.py) already listens:
        # the tests would talk to it, with other data / denied ranges, and
        # fail confusingly. Stop with a clear message instead.
        if is_port_open("127.0.0.1", self.port, timeout=0.5):
            pytest.fail(
                f"Port {self.port} is already in use, so the {self.name} test simulator "
                f"cannot start (is simulators/run_all.py or start_simulators.sh running?). "
                f"Stop it and run the integration tests again.",
                pytrace=False,
            )

        self.process = Process(target=self.start_func, daemon=True)
        self.process.start()

        # Wait for port to be available
        if not wait_for_port("127.0.0.1", self.port, timeout=10.0):
            self.stop()
            raise RuntimeError(f"Failed to start {self.name} simulator on port {self.port}")
    
    def stop(self):
        """Stop the simulator process"""
        if self.process and self.process.is_alive():
            self.process.terminate()
            self.process.join(timeout=5.0)
            if self.process.is_alive():
                self.process.kill()
        self.process = None
    
    def is_running(self) -> bool:
        """Check if simulator is running"""
        return self.process is not None and self.process.is_alive()


def run_slmp_simulator():
    """Run SLMP simulator in separate process"""
    import asyncio
    from simulators.slmp_simulator import run_server
    
    asyncio.run(run_server("127.0.0.1", 5001, [(5000, 5100), (7000, 7050)]))


def run_modbus_simulator():
    """Run Modbus simulator in separate process"""
    import asyncio
    from simulators.modbus_simulator import run_server
    
    asyncio.run(run_server("127.0.0.1", 5502, [(5000, 5100), (8000, 8050)]))


def run_ethernet_ip_simulator():
    """Run EtherNet/IP simulator in separate process"""
    import asyncio
    from simulators.ethernet_ip_simulator import run_server
    
    asyncio.run(run_server("127.0.0.1", 44818, [(100, 150)]))


def run_logix_simulator():
    """Run the EtherNet/IP simulator in Logix mode (symbolic tags)"""
    import asyncio
    from simulators.ethernet_ip_simulator import run_server
    
    asyncio.run(run_server("127.0.0.1", 44819, [], mode="logix"))


def run_omron_simulator():
    """Run the EtherNet/IP simulator in Omron NJ/NX mode (variables by name)"""
    import asyncio
    from simulators.ethernet_ip_simulator import run_server
    
    asyncio.run(run_server("127.0.0.1", 44820, [], mode="omron"))


def run_s7_simulator():
    """Run S7 simulator in separate process"""
    import asyncio
    from simulators.s7_simulator import run_server
    
    # Denied byte offsets 1000-1101 = word addresses 500-550 (byte = word * 2)
    asyncio.run(run_server("127.0.0.1", 1102, [(1000, 1101)]))


def run_fins_simulator():
    """Run FINS simulator in separate process"""
    import asyncio
    from simulators.fins_simulator import run_fins_simulator as run_sim
    
    asyncio.run(run_sim(host="127.0.0.1", port=9600))


@pytest.fixture(scope="session")
def slmp_simulator() -> Generator[SimulatorProcess, None, None]:
    """
    Fixture that starts SLMP simulator for the test session.
    
    Yields:
        SimulatorProcess: The running simulator
    """
    simulator = SimulatorProcess("SLMP", 5001, run_slmp_simulator)
    
    try:
        simulator.start()
        yield simulator
    finally:
        simulator.stop()


@pytest.fixture(scope="session")
def modbus_simulator() -> Generator[SimulatorProcess, None, None]:
    """
    Fixture that starts Modbus simulator for the test session.
    
    Yields:
        SimulatorProcess: The running simulator
    """
    simulator = SimulatorProcess("Modbus", 5502, run_modbus_simulator)
    
    try:
        simulator.start()
        yield simulator
    finally:
        simulator.stop()


@pytest.fixture(scope="session")
def ethernet_ip_simulator() -> Generator[SimulatorProcess, None, None]:
    """
    Fixture that starts EtherNet/IP simulator for the test session.
    
    Yields:
        SimulatorProcess: The running simulator
    """
    simulator = SimulatorProcess("EtherNet/IP", 44818, run_ethernet_ip_simulator)
    
    try:
        simulator.start()
        yield simulator
    finally:
        simulator.stop()


@pytest.fixture(scope="session")
def s7_simulator() -> Generator[SimulatorProcess, None, None]:
    """
    Fixture that starts S7 simulator for the test session.
    
    Yields:
        SimulatorProcess: The running simulator
    """
    simulator = SimulatorProcess("S7", 1102, run_s7_simulator)
    
    try:
        simulator.start()
        yield simulator
    finally:
        simulator.stop()


class UDPSimulatorProcess(SimulatorProcess):
    """Wrapper for UDP simulator process management"""
    
    def start(self):
        """Start the simulator process without TCP wait_for_port"""
        if self.is_running():
            return
        
        self.process = Process(target=self.start_func, daemon=True)
        self.process.start()
        
        # UDP uses connectionless socket, just sleep for a short time to let it bind
        time.sleep(0.5)


@pytest.fixture(scope="session")
def fins_simulator() -> Generator[SimulatorProcess, None, None]:
    """
    Fixture that starts FINS simulator for the test session.
    
    Yields:
        SimulatorProcess: The running simulator
    """
    # The simulator serves UDP and TCP on 9600; waiting for the TCP port
    # also confirms the process (and its UDP endpoint) is up
    simulator = SimulatorProcess("FINS", 9600, run_fins_simulator)
    
    try:
        simulator.start()
        yield simulator
    finally:
        simulator.stop()


@pytest.fixture(scope="session")
def all_simulators(
    slmp_simulator,
    modbus_simulator
) -> dict:
    """
    Fixture that starts all simulators.
    
    Yields:
        Dict of simulator name to SimulatorProcess
    """
    return {
        "slmp": slmp_simulator,
        "modbus": modbus_simulator,
    }


@pytest.fixture
def slmp_plc_info():
    """PLCInfo for SLMP simulator"""
    from plc_discovery.config import PLCInfo, Protocol
    return PLCInfo(
        ip_address="127.0.0.1",
        protocol=Protocol.SLMP,
        port=5001,
        manufacturer="Test Simulator",
    )


@pytest.fixture
def modbus_plc_info():
    """PLCInfo for Modbus simulator"""
    from plc_discovery.config import PLCInfo, Protocol
    return PLCInfo(
        ip_address="127.0.0.1",
        protocol=Protocol.MODBUS_TCP,
        port=5502,
        manufacturer="Test Simulator",
    )


@pytest.fixture
def fins_plc_info():
    """PLCInfo for FINS simulator"""
    from plc_discovery.config import PLCInfo, Protocol
    return PLCInfo(
        ip_address="127.0.0.1",
        protocol=Protocol.FINS,
        port=9600,
        manufacturer="Test Simulator",
    )


@pytest.fixture
def fins_tcp_handler(network_config):
    """FINSHandler using FINS/TCP against the simulator (not yet connected)"""
    from plc_discovery.protocols.fins import FINSHandler
    return FINSHandler("127.0.0.1", 9600, config=network_config, use_tcp=True)


@pytest.fixture(scope="session")
def logix_simulator() -> Generator[SimulatorProcess, None, None]:
    """EtherNet/IP simulator in Logix mode (tags) for the test session"""
    simulator = SimulatorProcess("EtherNet/IP Logix", 44819, run_logix_simulator)
    try:
        simulator.start()
        yield simulator
    finally:
        simulator.stop()


@pytest.fixture
def logix_plc_info():
    """PLCInfo for the Logix-mode EtherNet/IP simulator"""
    from plc_discovery.config import PLCInfo, Protocol
    return PLCInfo(ip_address="127.0.0.1", protocol=Protocol.ETHERNET_IP, port=44819)


@pytest.fixture(scope="session")
def omron_simulator() -> Generator[SimulatorProcess, None, None]:
    """EtherNet/IP simulator in Omron NJ/NX mode for the test session"""
    simulator = SimulatorProcess("EtherNet/IP Omron NJ/NX", 44820, run_omron_simulator)
    try:
        simulator.start()
        yield simulator
    finally:
        simulator.stop()


@pytest.fixture
def omron_plc_info():
    """PLCInfo for the Omron NJ/NX-mode EtherNet/IP simulator"""
    from plc_discovery.config import PLCInfo, Protocol
    return PLCInfo(ip_address="127.0.0.1", protocol=Protocol.ETHERNET_IP, port=44820)


@pytest.fixture
def ethernet_ip_plc_info():
    """PLCInfo for EtherNet/IP simulator"""
    from plc_discovery.config import PLCInfo, Protocol
    return PLCInfo(
        ip_address="127.0.0.1",
        protocol=Protocol.ETHERNET_IP,
        port=44818,
        manufacturer="Test Simulator",
    )


@pytest.fixture
def s7_plc_info():
    """PLCInfo for S7 simulator"""
    from plc_discovery.config import PLCInfo, Protocol
    return PLCInfo(
        ip_address="127.0.0.1",
        protocol=Protocol.S7,
        port=1102,
        manufacturer="Test Simulator",
    )


@pytest.fixture
def network_config():
    """NetworkConfig for testing"""
    from plc_discovery.config import NetworkConfig
    return NetworkConfig(
        discovery_timeout_ms=2000,
        discovery_retry_count=2,
        packet_interval_ms=10,
        retry_interval_ms=100,
        request_timeout_ms=3000,
        max_concurrent=1,
    )


