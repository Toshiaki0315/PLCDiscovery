"""
Regression tests for minor review findings.
"""

import asyncio
import json
import struct
import sys
import time

import pytest

import plc_scanner
from plc_discovery.broadcast_discovery import BroadcastDiscovery
from plc_discovery.config import DeviceType, NetworkConfig, PLCInfo, Protocol
from plc_discovery.config_loader import ConfigLoader
from plc_discovery.discovery import PLCDiscovery
from plc_discovery.utils import RateLimiter, parse_ip_range


def parse(monkeypatch, *argv):
    monkeypatch.setattr(sys, "argv", ["plc_scanner.py", *argv])
    return plc_scanner.parse_args()


# ---------------------------------------------------------------------------
# CLI options
# ---------------------------------------------------------------------------


class TestCLIOptions:

    def test_fins_protocol_option(self, monkeypatch):
        args = parse(monkeypatch, "--protocol", "fins")
        assert plc_scanner.get_protocol_from_string(args.protocol) == Protocol.FINS

    @pytest.mark.parametrize("device, expected", [("B", DeviceType.B), ("SM", DeviceType.SM)])
    def test_bit_device_options(self, monkeypatch, device, expected):
        args = parse(monkeypatch, "--device", device)
        assert plc_scanner.get_device_type_from_string(args.device) == expected

    def test_db_track_history_can_be_disabled(self, monkeypatch):
        assert parse(monkeypatch).db_track_history is True
        assert parse(monkeypatch, "--no-db-track-history").db_track_history is False


class TestAddressRange:

    @pytest.mark.parametrize("text, expected", [("0-999", (0, 999)), ("100", (100, 100)), (" 5 - 7 ", (5, 7))])
    def test_valid(self, text, expected):
        assert plc_scanner.parse_address_range(text) == expected

    @pytest.mark.parametrize("text", ["100-50", "abc", "1-2-3", "-5"])
    def test_invalid(self, text):
        with pytest.raises(ValueError):
            plc_scanner.parse_address_range(text)


class TestConfigValidation:

    def load(self, tmp_path, data):
        path = tmp_path / "config.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        loader = ConfigLoader(str(path))
        loader.load()
        return loader

    def test_negative_start_rejected(self, tmp_path):
        loader = self.load(tmp_path, {"scan": {"device_ranges": [{"device": "D", "start": -1, "end": 5}]}})
        assert any("start must be >= 0" in e for e in loader.validate())

    def test_unknown_device_rejected(self, tmp_path):
        loader = self.load(tmp_path, {"scan": {"device_ranges": [{"device": "QQ", "start": 0, "end": 5}]}})
        assert any("unknown device" in e for e in loader.validate())

    def test_bit_devices_accepted(self, tmp_path):
        loader = self.load(tmp_path, {"scan": {"device_ranges": [{"device": "SM", "start": 0, "end": 5}]}})
        assert loader.validate() == []
        assert loader.get_device_ranges()[0].device_type == DeviceType.SM


# ---------------------------------------------------------------------------
# IP range parsing
# ---------------------------------------------------------------------------


class TestParseIPRange:

    def test_full_range(self):
        assert parse_ip_range("192.168.1.254-192.168.2.1") == [
            "192.168.1.254",
            "192.168.1.255",
            "192.168.2.0",
            "192.168.2.1",
        ]

    @pytest.mark.parametrize(
        "text",
        [
            "192.168.1.1-999",  # octet out of range
            "192.168.1.10-5",  # reversed
            "192.168.1.300-310",  # invalid base
            "192.168.1.1-192.168.1.x",  # invalid end
        ],
    )
    def test_invalid_returns_empty(self, text):
        assert parse_ip_range(text) == []


# ---------------------------------------------------------------------------
# SLMP broadcast request
# ---------------------------------------------------------------------------


def test_slmp_discovery_request_length_field():
    request = BroadcastDiscovery()._build_slmp_discovery_request()
    # subheader(2) + routing(5) + data length(2) + payload
    (data_length,) = struct.unpack("<H", request[7:9])
    assert data_length == len(request) - 9 == 6


# ---------------------------------------------------------------------------
# Rate limiter uses a monotonic clock
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rate_limiter_ignores_wall_clock(monkeypatch):
    limiter = RateLimiter(50)
    await limiter.wait()
    # Wall clock jumping backwards must not cause a long sleep
    monkeypatch.setattr(time, "time", lambda: 0.0)
    started = time.monotonic()
    await limiter.wait()
    assert time.monotonic() - started < 0.5


# ---------------------------------------------------------------------------
# Large-range discovery is batched lazily
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_probe_hosts_batched(monkeypatch):
    discovery = PLCDiscovery(NetworkConfig(max_concurrent=1, discovery_timeout_ms=1))
    created = []
    active = {"now": 0, "max": 0}

    async def fake_probe(ip, mac=None):
        active["now"] += 1
        active["max"] = max(active["max"], active["now"])
        await asyncio.sleep(0)
        active["now"] -= 1
        return [PLCInfo(ip, protocol=Protocol.SLMP, port=5001)] if ip.endswith(".7") else []

    def counting_probe(ip, mac=None):
        created.append(ip)
        return fake_probe(ip, mac)

    monkeypatch.setattr(discovery, "_probe_host_all", counting_probe)
    hosts = [f"10.0.0.{i}" for i in range(1, 31)]
    await discovery._probe_hosts(hosts, {})

    assert created == hosts
    assert active["max"] <= 10  # max_concurrent * 10
    assert [p.ip_address for p in discovery.discovered_plcs.values()] == ["10.0.0.7"]


# ---------------------------------------------------------------------------
# GUI worker waits for cleanup on shutdown
# ---------------------------------------------------------------------------


def _import_async_worker(monkeypatch):
    """Import plc_gui.AsyncWorker, stubbing tkinter when Tk is not installed"""
    try:
        import tkinter  # noqa: F401
    except ImportError:
        from unittest.mock import MagicMock

        tk = MagicMock()
        monkeypatch.setitem(sys.modules, "tkinter", tk)
        for name in ("filedialog", "messagebox", "ttk"):
            monkeypatch.setitem(sys.modules, f"tkinter.{name}", getattr(tk, name))
        monkeypatch.delitem(sys.modules, "plc_gui", raising=False)
    from plc_gui import AsyncWorker

    return AsyncWorker


def test_gui_worker_shutdown_waits_for_cleanup(monkeypatch):
    AsyncWorker = _import_async_worker(monkeypatch)

    worker = AsyncWorker()
    state = {"started": False, "cleaned": False}

    async def job():
        state["started"] = True
        try:
            await asyncio.sleep(60)
        finally:
            await asyncio.sleep(0.05)  # e.g. PLC disconnect
            state["cleaned"] = True

    worker.submit(job(), lambda exc: None)
    deadline = time.monotonic() + 2
    while not state["started"] and time.monotonic() < deadline:
        time.sleep(0.01)

    worker.shutdown(timeout=2)
    assert state["cleaned"] is True
