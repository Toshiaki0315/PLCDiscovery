"""
Regression tests for the fourth review's minor findings.
"""

import asyncio
import json
import socket
import threading
from unittest.mock import MagicMock, patch

import pytest

import plc_scanner
from plc_discovery.collector import PLCDataCollector
from plc_discovery.config import (
    DataPoint, DeviceRange, DeviceType, NetworkConfig, PLCInfo, Protocol, ScanMode, StatusCode
)
from plc_discovery.config_loader import ConfigLoader
from plc_discovery.probes import probe_fins_udp


# ---------------------------------------------------------------------------
# 1: invalid option values fail only that target
# ---------------------------------------------------------------------------

def load(tmp_path, targets):
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"targets": targets}), encoding="utf-8")
    loader = ConfigLoader(str(path))
    loader.load()
    return loader


@pytest.mark.parametrize("protocol, options, message", [
    ("fins", {"dest_node": 300}, "dest_node must be an integer 0-254"),
    ("fins_tcp", {"source_node": -1}, "source_node must be an integer 0-254"),
    ("s7", {"slot": 99}, "slot must be an integer 0-31"),
    ("s7", {"db_number": 0}, "db_number must be an integer 1-65535"),
    ("modbus", {"unit_id": "1"}, "unit_id must be an integer 0-255"),
    ("eip", {"slot": True}, "slot must be an integer 0-255"),
])
def test_validate_rejects_out_of_range_options(tmp_path, protocol, options, message):
    loader = load(tmp_path, [{"ip": "10.0.0.1", "protocol": protocol, "options": options}])
    assert any(message in e for e in loader.validate())


def test_validate_accepts_valid_options(tmp_path):
    loader = load(tmp_path, [
        {"ip": "10.0.0.1", "protocol": "fins", "options": {"dest_node": 0, "source_node": 254}},
        {"ip": "10.0.0.2", "protocol": "s7", "options": {"rack": 0, "slot": 2, "db_number": 100}},
    ])
    assert loader.validate() == []


@pytest.mark.asyncio
async def test_collector_bad_option_value_returns_false():
    plc = PLCInfo("127.0.0.1", protocol=Protocol.FINS, port=9600, options={"dest_node": 300})
    collector = PLCDataCollector(plc)
    assert await collector.connect() is False          # previously raised ValueError
    assert "dest_node must be 0-254" in collector.connect_error


@pytest.mark.asyncio
async def test_bad_target_does_not_stop_other_targets(tmp_path):
    """Sequential CLI scan: the invalid target fails, the next one is still scanned"""
    good = PLCInfo("10.0.0.2", protocol=Protocol.SLMP, port=5001)
    bad = PLCInfo("10.0.0.1", protocol=Protocol.FINS, port=9600, options={"dest_node": 300})

    class GoodCollector:
        is_connected = True
        connect_error = None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

        async def collect_range(self, *a):
            return [DataPoint("D0", 1, "0x0001", StatusCode.OK)]

        def get_denied_addresses(self):
            return set()

        def get_denied_statuses(self):
            return {}

        def get_statistics(self):
            return {"total_points": 1, "success_count": 1, "error_count": 0}

    def make(plc, config):
        return GoodCollector() if plc is good else PLCDataCollector(plc, config)

    class Display:
        def __getattr__(self, name):
            return lambda *a, **k: None

    exporter = MagicMock()
    with patch.object(plc_scanner, "PLCDataCollector", make):
        outcomes = [
            await plc_scanner.run_single_scan(
                plc, NetworkConfig(), exporter, Display(), ScanMode.RANGE,
                [DeviceRange(DeviceType.D, 0, 0)],
            )
            for plc in (bad, good)
        ]

    assert outcomes[0].success is False
    assert "invalid options" in outcomes[0].error and "dest_node" in outcomes[0].error
    assert outcomes[1].success is True


# ---------------------------------------------------------------------------
# 2: FINS/UDP probe uses the same node numbers as FINSHandler
# ---------------------------------------------------------------------------

def test_fins_udp_probe_uses_ip_derived_nodes():
    received = []
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(2)
    port = srv.getsockname()[1]

    def respond():
        data, addr = srv.recvfrom(2048)
        received.append(data)
        header = bytes([0xC0, 0, 2, data[6], data[7], data[8], data[3], data[4], data[5], data[9]])
        srv.sendto(header + data[10:12] + b"\x00\x00\x00\x00", addr)

    thread = threading.Thread(target=respond, daemon=True)
    thread.start()
    try:
        assert probe_fins_udp("127.0.0.1", port, 2.0)
    finally:
        thread.join(2)
        srv.close()

    request = received[0]
    assert request[4] == 1   # DA1 = last octet of 127.0.0.1
    assert request[7] == 1   # SA1 = last octet of the local address (127.0.0.1)
