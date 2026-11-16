"""
Regression tests for the second review's findings (R1-R6).
"""

import asyncio
import socket
import struct
import threading
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest

import plc_scanner
from plc_discovery.config import (
    DataPoint, DeviceRange, DeviceType, NetworkConfig, PLCInfo, Protocol, StatusCode
)
from plc_discovery.data_types import ByteOrder, DataType
from plc_discovery.discovery import PLCDiscovery
from plc_discovery.output import CSVExporter
from plc_discovery.probes import (
    probe_ethernet_ip, probe_modbus, probe_s7, probe_slmp, verify_protocol
)
from plc_discovery.protocols.base import BaseProtocolHandler
from plc_discovery.protocols.ethernet_ip import EtherNetIPHandler, is_slc_identity
from plc_discovery.protocols.modbus import ModbusHandler
from plc_discovery.retry import RetryConfig, RetryStrategy


# ---------------------------------------------------------------------------
# R1: cached denied addresses in the middle of a chunk are skipped
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_r1_denied_address_mid_chunk_skipped_next_scan():
    calls = []

    class Handler(BaseProtocolHandler):
        protocol = Protocol.SLMP

        async def connect(self):
            return True

        async def disconnect(self):
            pass

        async def read_device_raw(self, device_type, start, count):
            calls.append((start, count))
            if start <= 10 <= start + count - 1:
                return None, StatusCode.NG_ILLEGAL_ADDR
            return [start] * count, StatusCode.OK

    handler = Handler(
        "127.0.0.1", 5001, NetworkConfig(packet_interval_ms=0, retry_interval_ms=0),
        retry_config=RetryConfig(strategy=RetryStrategy.FIXED, max_retries=0, initial_delay_ms=0),
        use_circuit_breaker=False,
    )
    handler._connected = True
    rng = DeviceRange(DeviceType.D, 0, 899)

    first = await handler.read_device_range(rng)
    calls.clear()
    second = await handler.read_device_range(rng)

    assert calls == [(0, 10), (11, 889)]  # no failed read, no binary search
    assert [dp.address for dp in second] == [dp.address for dp in first]
    assert [dp.status for dp in second] == [dp.status for dp in first]
    assert second[10].status == StatusCode.NG_ILLEGAL_ADDR


# ---------------------------------------------------------------------------
# R2: words consumed by multi-word conversion stay in the CSV
# ---------------------------------------------------------------------------

def test_r2_csv_keeps_second_word(tmp_path):
    points = [
        DataPoint("D0", 0x0000, "0x0000", StatusCode.OK),
        DataPoint("D1", 0x3F80, "0x3F80", StatusCode.OK),
    ]
    converted = plc_scanner.apply_data_type_conversion(points, DataType.FLOAT, ByteOrder.LITTLE_ENDIAN)
    path = CSVExporter(str(tmp_path)).export_plc_data(converted, "1.2.3.4")
    lines = open(path, encoding="utf-8").read().splitlines()

    assert len(lines) == 3  # header + D0 + D1
    assert lines[1].startswith("D0,0,0x0000,FLOAT,1.0,")
    assert lines[2].startswith("D1,16256,0x3F80,FLOAT,,(part of D0),OK")


# ---------------------------------------------------------------------------
# R3: discovery requires a protocol reply, not just an open port
# ---------------------------------------------------------------------------

@contextmanager
def tcp_server(respond):
    """One-shot-per-connection TCP server; respond(request) -> reply bytes"""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    stop = threading.Event()

    def serve():
        srv.settimeout(0.1)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            with conn:
                conn.settimeout(1)
                try:
                    req = conn.recv(512)
                    reply = respond(req)
                    if reply:
                        conn.sendall(reply)
                except OSError:
                    pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield srv.getsockname()[1]
    finally:
        stop.set()
        thread.join(1)
        srv.close()


HTTP = lambda req: b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"


class TestR3Probes:

    def test_slmp_error_reply_counts(self):
        reply = b"\xD0\x00\x00\xFF\xFF\x03\x00\x02\x00\x59\xC0"  # end code C059
        with tcp_server(lambda req: reply) as port:
            assert probe_slmp("127.0.0.1", port, 1.0)

    def test_modbus_requires_matching_transaction(self):
        def respond(req):
            return req[:2] + b"\x00\x00\x00\x05\x01\x03\x02\x00\x2A"
        with tcp_server(respond) as port:
            assert probe_modbus("127.0.0.1", port, 1.0)
        with tcp_server(lambda req: b"\x99\x99" + respond(req)[2:]) as port:
            assert not probe_modbus("127.0.0.1", port, 1.0)

    def test_s7_connection_confirm(self):
        cc = b"\x03\x00\x00\x16\x11\xD0" + b"\x00" * 16
        with tcp_server(lambda req: cc) as port:
            assert probe_s7("127.0.0.1", port, 1.0)

    def test_eip_list_identity_context_echo(self):
        def respond(req):
            return struct.pack("<HHII", 0x0063, 0, 0, 0) + req[12:20] + b"\x00" * 4
        with tcp_server(respond) as port:
            assert probe_ethernet_ip("127.0.0.1", port, 1.0)

    @pytest.mark.parametrize("protocol", list(Protocol))
    def test_non_plc_service_rejected(self, protocol):
        with tcp_server(HTTP) as port:
            assert not verify_protocol("127.0.0.1", port, protocol, 1.0)

    @pytest.mark.asyncio
    async def test_open_port_without_protocol_not_reported(self):
        discovery = PLCDiscovery(NetworkConfig(discovery_timeout_ms=200))
        with patch("plc_discovery.discovery.is_port_open", side_effect=lambda ip, p, t: p == 5001), \
                patch("plc_discovery.discovery.verify_protocol", return_value=False):
            assert await discovery._probe_host("192.0.2.10") is None


# ---------------------------------------------------------------------------
# R4: pymodbus internal retries disabled
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_r4_modbus_client_without_internal_retries():
    with patch("pymodbus.client.ModbusTcpClient") as client_cls:
        client_cls.return_value.connect.return_value = True
        handler = ModbusHandler("127.0.0.1", 502, config=NetworkConfig())
        assert await handler.connect()
    assert client_cls.call_args.kwargs["retries"] == 0


# ---------------------------------------------------------------------------
# R5: periodic scans read every target each cycle
# ---------------------------------------------------------------------------

class FakeCollector:
    def __init__(self, ip, connected=True):
        self.ip = ip
        self.is_connected = connected
        self.collect_calls = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    def clear_data(self):
        pass

    async def collect_range(self, *args):
        self.collect_calls += 1
        return [DataPoint("D0", 1, "0x0001", StatusCode.OK)]

    def get_denied_addresses(self):
        return set()

    def get_denied_statuses(self):
        return {}

    def get_statistics(self):
        return {"total_points": 1, "success_count": 1, "error_count": 0}


class Display:
    def __getattr__(self, name):
        return lambda *a, **k: None


@pytest.mark.asyncio
async def test_r5_periodic_scan_round_robin():
    collectors = {
        "10.0.0.1": FakeCollector("10.0.0.1"),
        "10.0.0.2": FakeCollector("10.0.0.2", connected=False),
        "10.0.0.3": FakeCollector("10.0.0.3"),
    }
    plcs = [PLCInfo(ip, protocol=Protocol.SLMP, port=5001) for ip in collectors]
    exporter = MagicMock()

    with patch.object(plc_scanner, "PLCDataCollector", lambda plc, cfg: collectors[plc.ip_address]):
        task = asyncio.ensure_future(plc_scanner.run_periodic_scan(
            plcs, NetworkConfig(), exporter, Display(),
            [DeviceRange(DeviceType.D, 0, 0)], interval=0.01
        ))
        while collectors["10.0.0.3"].collect_calls < 3:
            await asyncio.sleep(0.005)
        task.cancel()
        outcomes = {o.ip_address: o for o in await task}

    assert collectors["10.0.0.1"].collect_calls >= 3
    # unreachable at the start: still polled every cycle (reconnect is retried)
    assert collectors["10.0.0.2"].collect_calls >= 2
    assert outcomes["10.0.0.1"].success and outcomes["10.0.0.3"].success
    assert not outcomes["10.0.0.2"].success
    assert "Failed to connect" in outcomes["10.0.0.2"].error
    exported_ips = {c.args[1] for c in exporter.export_plc_data.call_args_list}
    assert exported_ips == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}


# ---------------------------------------------------------------------------
# R6: SLC driver only for real SLC/PLC-5/MicroLogix controllers
# ---------------------------------------------------------------------------

class TestR6SLCIdentity:

    @pytest.mark.parametrize("identity, expected", [
        ({"vendor": "Rockwell Automation/Allen-Bradley", "product_type": "Programmable Logic Controller",
          "product_name": "1747-L552/C C/10 - DC 3.46"}, True),
        ({"vendor": "Rockwell Automation/Allen-Bradley", "product_type": "Programmable Logic Controller",
          "product_name": "1766-L32BWA B/14.00 MicroLogix 1400"}, True),
        ({"vendor": "Rockwell Automation/Allen-Bradley", "product_type": "Programmable Logic Controller",
          "product_name": "1756-L71/B LOGIX5571"}, False),
        ({"vendor": "OMRON Corporation", "product_type": "Programmable Logic Controller",
          "product_name": "NJ501-1300"}, False),
        ({"vendor": "Rockwell Automation/Allen-Bradley", "product_type": "Communications Adapter",
          "product_name": "1756-EN2T"}, False),
        (None, False),
    ])
    def test_is_slc_identity(self, identity, expected):
        assert is_slc_identity(identity) is expected

    @pytest.mark.asyncio
    async def test_non_slc_device_rejected(self):
        handler = EtherNetIPHandler("127.0.0.1", config=NetworkConfig())
        driver = MagicMock()
        driver._list_identity.return_value = {
            "vendor": "OMRON Corporation", "product_type": "Programmable Logic Controller",
            "product_name": "NJ501-1300",
        }
        with patch("pycomm3.SLCDriver", return_value=driver):
            assert await handler._connect_slc() is False
        driver.close.assert_called_once()
        assert handler._plc_type is None
