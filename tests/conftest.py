"""
Pytest Configuration and Shared Fixtures
"""

import sys
import tempfile
from unittest.mock import MagicMock

import pytest

# Python without Tk (pyenv / Homebrew builds without tcl-tk, slim Docker
# images): the GUI modules (plc_gui, plc_gui_settings, simulator_gui) import
# tkinter at the top, so a test module importing them failed to load and
# pytest stopped before running any test ("errors during collection").
# Their tests call the GUI's logic, not real windows: a stand-in module is
# enough. Installed before the test modules are collected.
try:
    import tkinter  # noqa: F401
except ImportError:
    _tk = MagicMock()
    sys.modules["tkinter"] = _tk
    for _name in ("filedialog", "messagebox", "scrolledtext", "simpledialog", "ttk"):
        sys.modules[f"tkinter.{_name}"] = getattr(_tk, _name)

from plc_discovery.config import DataPoint, DeviceRange, DeviceType, NetworkConfig, PLCInfo, Protocol, StatusCode


@pytest.fixture(autouse=True)
def _slmp_identity_follows_a_patched_verify_protocol(monkeypatch):
    """
    Discovery verifies SLMP with identify_slmp() / identify_slmp_udp()
    (frame, data code and CPU model in one probe) and every other protocol
    with verify_protocol().
    Tests that replace verify_protocol to fake a network expect it to decide
    for SLMP as well: while it is replaced, SLMP follows it (as a 3E binary
    port without a model name). Otherwise the real probe runs, for loopback
    addresses only (simulators): the unit tests never connect to other hosts
    (an SLMP target given with --protocol is probed for its frame / data code).
    """
    from plc_discovery import discovery as discovery_module
    from plc_discovery import probes

    def follow(real, protocol):
        def identify(ip, port, timeout, interval=0.0):
            verify = discovery_module.verify_protocol
            if verify is probes.verify_protocol:
                return real(ip, port, timeout, interval) if str(ip).startswith("127.") else None
            if not verify(ip, port, protocol, timeout):
                return None
            return {"frame": "3E", "ascii": False, "end_code": 0, "model": None, "model_code": None}

        return identify

    monkeypatch.setattr(discovery_module, "identify_slmp", follow(discovery_module.identify_slmp, Protocol.SLMP))
    monkeypatch.setattr(
        discovery_module, "identify_slmp_udp", follow(discovery_module.identify_slmp_udp, Protocol.SLMP_UDP)
    )


@pytest.fixture
def sample_plc_info():
    """Sample PLCInfo for testing"""
    return PLCInfo(
        ip_address="192.168.1.10",
        mac_address="00:26:92:12:34:56",
        manufacturer="三菱電機",
        model="iQ-R Series",
        protocol=Protocol.SLMP,
        port=5001,
        cpu_type="R04CPU",
        firmware_version="1.0",
    )


@pytest.fixture
def sample_plc_list():
    """Sample list of PLCInfo for testing"""
    return [
        PLCInfo(
            ip_address="192.168.1.10",
            mac_address="00:26:92:12:34:56",
            manufacturer="三菱電機",
            model="iQ-R Series",
            protocol=Protocol.SLMP,
            port=5001,
        ),
        PLCInfo(
            ip_address="192.168.1.20",
            mac_address="00:00:0A:AB:CD:EF",
            manufacturer="オムロン",
            model="NJ Series",
            protocol=Protocol.ETHERNET_IP,
            port=44818,
        ),
        PLCInfo(
            ip_address="192.168.1.30",
            mac_address="00:1B:1B:11:22:33",
            manufacturer="シーメンス",
            model="S7-1500",
            protocol=Protocol.S7,
            port=102,
        ),
    ]


@pytest.fixture
def sample_data_points():
    """Sample DataPoint list for testing"""
    return [
        DataPoint(address="D0", value=100, raw_hex="0x0064", status=StatusCode.OK, timestamp="2024-01-01 10:00:00.000"),
        DataPoint(address="D1", value=200, raw_hex="0x00C8", status=StatusCode.OK, timestamp="2024-01-01 10:00:00.001"),
        DataPoint(
            address="D2",
            value=None,
            raw_hex=None,
            status=StatusCode.NG_ILLEGAL_ADDR,
            timestamp="2024-01-01 10:00:00.002",
        ),
        DataPoint(
            address="D3", value=None, raw_hex=None, status=StatusCode.NG_TIMEOUT, timestamp="2024-01-01 10:00:00.003"
        ),
    ]


@pytest.fixture
def sample_device_range():
    """Sample DeviceRange for testing"""
    return DeviceRange(device_type=DeviceType.D, start_address=0, end_address=99)


@pytest.fixture
def network_config():
    """Sample NetworkConfig for testing"""
    return NetworkConfig(
        discovery_timeout_ms=500,
        discovery_retry_count=2,
        packet_interval_ms=10,
        retry_interval_ms=50,
        request_timeout_ms=1000,
        max_concurrent=1,
    )


@pytest.fixture
def temp_output_dir():
    """Temporary directory for output files"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def mock_slmp_client():
    """Mock SLMP client"""
    mock = MagicMock()
    mock.connect = MagicMock()
    mock.close = MagicMock()
    mock.batchread_wordunits = MagicMock(return_value=[100, 200, 300])
    mock.batchread_bitunits = MagicMock(return_value=[0, 1, 0, 1])
    return mock


@pytest.fixture
def mock_modbus_client():
    """Mock Modbus client"""
    mock = MagicMock()
    mock.connect = MagicMock(return_value=True)
    mock.close = MagicMock()

    # Mock read response
    read_response = MagicMock()
    read_response.isError = MagicMock(return_value=False)
    read_response.registers = [100, 200, 300]

    mock.read_holding_registers = MagicMock(return_value=read_response)
    mock.read_input_registers = MagicMock(return_value=read_response)
    return mock


@pytest.fixture
def mock_s7_client():
    """Mock S7 client"""
    mock = MagicMock()
    mock.connect = MagicMock()
    mock.disconnect = MagicMock()
    mock.db_read = MagicMock(return_value=bytearray([0x00, 0x64, 0x00, 0xC8]))

    # Mock CPU info
    cpu_info = MagicMock()
    cpu_info.ModuleTypeName = b"CPU 1515-2 PN"
    cpu_info.ASName = b"S7-1500"
    cpu_info.SerialNumber = b"S C-12345"
    cpu_info.OrderCode = b"6ES7 515-2AM02-0AB0"
    mock.get_cpu_info = MagicMock(return_value=cpu_info)

    return mock
