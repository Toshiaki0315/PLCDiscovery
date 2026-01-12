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
    from simulators.slmp_simulator import SLMPSimulator
    
    async def main():
        simulator = SLMPSimulator(host="127.0.0.1", port=5001)
        await simulator.start()
        # Keep running
        while True:
            await asyncio.sleep(1)
    
    asyncio.run(main())


def run_modbus_simulator():
    """Run Modbus simulator in separate process"""
    import asyncio
    from simulators.modbus_simulator import ModbusSimulator
    
    async def main():
        simulator = ModbusSimulator(host="127.0.0.1", port=5502)  # Use non-privileged port
        await simulator.start()
        while True:
            await asyncio.sleep(1)
    
    asyncio.run(main())


def run_ethernet_ip_simulator():
    """Run EtherNet/IP simulator in separate process"""
    import asyncio
    from simulators.ethernet_ip_simulator import EtherNetIPSimulator
    
    async def main():
        simulator = EtherNetIPSimulator(host="127.0.0.1", port=44818)
        await simulator.start()
        while True:
            await asyncio.sleep(1)
    
    asyncio.run(main())


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


