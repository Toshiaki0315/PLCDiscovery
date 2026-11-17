"""
FINS/TCP Integration Tests

Tests FINSHandler(use_tcp=True) and the FINS/TCP discovery probe against
the FINS simulator's TCP server (same port as UDP).
"""

import asyncio
import socket
import struct

import pytest

from plc_discovery.config import DeviceRange, DeviceType, Protocol, StatusCode
from plc_discovery.probes import probe_fins_tcp, verify_protocol
from plc_discovery.protocols.fins import FINSHandler

# async tests run via pytest-asyncio auto mode (pytest.ini); the raw-socket
# and probe tests are synchronous
pytestmark = pytest.mark.integration


class TestFINSTCPConnection:

    async def test_handshake_assigns_node_addresses(self, fins_simulator, fins_tcp_handler):
        assert await fins_tcp_handler.connect() is True
        try:
            assert fins_tcp_handler.is_connected
            assert 0 < fins_tcp_handler.source_node < 255   # allocated client node
            assert fins_tcp_handler.dest_node == 1          # simulator PLC node
        finally:
            await fins_tcp_handler.disconnect()
        assert not fins_tcp_handler.is_connected

    async def test_each_connection_gets_own_node(self, fins_simulator, network_config):
        a = FINSHandler("127.0.0.1", fins_simulator.port, config=network_config, use_tcp=True)
        b = FINSHandler("127.0.0.1", fins_simulator.port, config=network_config, use_tcp=True)
        assert await a.connect() and await b.connect()
        try:
            assert a.source_node != b.source_node
        finally:
            await a.disconnect()
            await b.disconnect()

    async def test_connect_wrong_port_fails(self, fins_simulator, network_config):
        handler = FINSHandler("127.0.0.1", 59999, config=network_config, use_tcp=True)
        assert await handler.connect() is False
        assert handler._writer is None


class TestFINSTCPRead:

    async def test_read_known_values(self, fins_simulator, fins_tcp_handler):
        await fins_tcp_handler.connect()
        try:
            data, status = await fins_tcp_handler.read_device_raw(DeviceType.DM, 100, 5)
            assert status == StatusCode.OK
            assert data == [1000, 1010, 1020, 1030, 1040]   # DM[n] = n * 10 for 100-199

            data, status = await fins_tcp_handler.read_device_raw(DeviceType.HR, 10, 3)
            assert status == StatusCode.OK
            assert data == [20, 22, 24]                    # HR[n] = n * 2
        finally:
            await fins_tcp_handler.disconnect()

    async def test_matches_udp_results(self, fins_simulator, network_config):
        """UDP and TCP share one simulated memory image"""
        udp = FINSHandler("127.0.0.1", fins_simulator.port, config=network_config)
        tcp = FINSHandler("127.0.0.1", fins_simulator.port, config=network_config, use_tcp=True)
        assert await udp.connect() and await tcp.connect()
        try:
            udp_data, _ = await udp.read_device_raw(DeviceType.DM, 0, 50)
            tcp_data, _ = await tcp.read_device_raw(DeviceType.DM, 0, 50)
            assert udp_data == tcp_data
        finally:
            await udp.disconnect()
            await tcp.disconnect()

    async def test_large_range_is_chunked(self, fins_simulator, fins_tcp_handler):
        await fins_tcp_handler.connect()
        try:
            points = await fins_tcp_handler.read_device_range(DeviceRange(DeviceType.DM, 300, 999))
            assert len(points) == 700
            assert all(dp.status == StatusCode.OK for dp in points)
            assert points[0].value == 300 and points[-1].value == 999   # DM[n] = n
        finally:
            await fins_tcp_handler.disconnect()

    async def test_illegal_address_reported(self, fins_simulator, fins_tcp_handler):
        await fins_tcp_handler.connect()
        try:
            data, status = await fins_tcp_handler.read_device_raw(DeviceType.DM, 5000, 1)
            assert (data, status) == (None, StatusCode.NG_ILLEGAL_ADDR)
        finally:
            await fins_tcp_handler.disconnect()

    async def test_binary_search_isolates_denied(self, fins_simulator, fins_tcp_handler):
        await fins_tcp_handler.connect()
        try:
            points = await fins_tcp_handler.read_device_range(DeviceRange(DeviceType.DM, 4990, 5110))
        finally:
            await fins_tcp_handler.disconnect()
        denied = [dp.address for dp in points if dp.status == StatusCode.NG_ILLEGAL_ADDR]
        ok = [dp.address for dp in points if dp.status == StatusCode.OK]
        assert denied == [f"DM{i}" for i in range(5000, 5101)]
        assert len(ok) == 20  # DM4990-4999 and DM5101-5110

    async def test_reconnects_after_broken_stream(self, fins_simulator, fins_tcp_handler):
        """A broken connection is re-established before the next request"""
        await fins_tcp_handler.connect()
        try:
            fins_tcp_handler._writer.transport.abort()   # simulate a dropped link
            await asyncio.sleep(0.05)

            _, status = await fins_tcp_handler.read_device_raw(DeviceType.DM, 300, 1)
            assert status != StatusCode.OK
            assert fins_tcp_handler._needs_reconnect

            data, status = await fins_tcp_handler.read_device_raw(DeviceType.DM, 300, 1)
            assert (data, status) == ([300], StatusCode.OK)
        finally:
            await fins_tcp_handler.disconnect()


class TestFINSTCPFraming:
    """Raw socket checks of the simulator's FINS/TCP framing"""

    @staticmethod
    def _connect(port):
        sock = socket.create_connection(("127.0.0.1", port), timeout=2)
        sock.settimeout(2)
        return sock

    @staticmethod
    def _recv_frame(sock):
        header = b""
        while len(header) < 16:
            header += sock.recv(16 - len(header))
        length = struct.unpack(">I", header[4:8])[0]
        body = b""
        while len(body) < length - 8:
            body += sock.recv(length - 8 - len(body))
        return header, body

    def test_frame_split_across_packets(self, fins_simulator):
        """The server reassembles frames that arrive in pieces"""
        handshake = b"FINS" + struct.pack(">IIII", 12, 0, 0, 0)
        with self._connect(fins_simulator.port) as sock:
            sock.sendall(handshake[:5])
            sock.sendall(handshake[5:])
            header, body = self._recv_frame(sock)
        assert header[:4] == b"FINS"
        assert struct.unpack(">I", header[8:12])[0] == 1   # node address response
        assert len(body) == 8

    def test_fins_frame_before_handshake_rejected(self, fins_simulator):
        fins = bytes([0x80, 0, 2, 0, 1, 0, 0, 10, 0, 1, 0x01, 0x01, 0x82, 0, 0, 0, 0, 1])
        frame = b"FINS" + struct.pack(">III", 8 + len(fins), 2, 0) + fins
        with self._connect(fins_simulator.port) as sock:
            sock.sendall(frame)
            header, _ = self._recv_frame(sock)
        command, error = struct.unpack(">II", header[8:16])
        assert command == 3 and error == 3   # error notification: unsupported

    def test_bad_magic_closes_connection(self, fins_simulator):
        with self._connect(fins_simulator.port) as sock:
            sock.sendall(b"XXXX" + b"\x00" * 12)
            header, _ = self._recv_frame(sock)
            assert struct.unpack(">II", header[8:16]) == (3, 1)
            assert sock.recv(16) == b""      # server closed


FINS_VARIANTS = (Protocol.FINS, Protocol.FINS_TCP)


class TestFINSTCPProbe:

    def test_probe_detects_simulator(self, fins_simulator):
        assert probe_fins_tcp("127.0.0.1", fins_simulator.port, 2.0)

    @pytest.mark.parametrize("protocol", FINS_VARIANTS)
    def test_both_fins_transports_verified(self, fins_simulator, protocol):
        assert verify_protocol("127.0.0.1", fins_simulator.port, protocol, 2.0)

    @pytest.mark.parametrize("protocol", [p for p in Protocol if p not in FINS_VARIANTS])
    def test_other_probes_do_not_match(self, fins_simulator, protocol):
        assert not verify_protocol("127.0.0.1", fins_simulator.port, protocol, 1.0)


class TestFINSTCPSelection:
    """FINS/TCP selected through the normal protocol mechanism (CLI/config/GUI)"""

    async def test_collector_uses_tcp_handler(self, fins_simulator, network_config):
        from plc_discovery.collector import PLCDataCollector
        from plc_discovery.config import PLCInfo

        plc = PLCInfo("127.0.0.1", protocol=Protocol.FINS_TCP, port=fins_simulator.port)
        async with PLCDataCollector(plc, network_config) as collector:
            assert collector._handler.use_tcp is True
            assert collector._handler._writer is not None   # TCP stream, not UDP
            points = await collector.collect_range(DeviceType.HR, 0, 9)
        assert [dp.value for dp in points] == [i * 2 for i in range(10)]

    def test_cli_range_scan_over_fins_tcp(self, fins_simulator, tmp_path, monkeypatch):
        import csv
        import sys
        import plc_scanner

        monkeypatch.setattr(sys, "argv", [
            "plc_scanner.py", "--mode", "range", "--target", "127.0.0.1",
            "--protocol", "fins-tcp", "--device", "DM", "--range", "300-304",
            "-q", "--output-dir", str(tmp_path),
        ])
        plc_scanner.cli()   # returns normally on success (no SystemExit)

        (data_file,) = tmp_path.glob("plc_data_127_0_0_1_*.csv")
        rows = list(csv.DictReader(open(data_file, encoding="utf-8-sig")))   # CLI default: UTF-8 with BOM
        assert [(r["address"], r["value"], r["status"]) for r in rows] == [
            (f"DM{i}", str(i), "OK") for i in range(300, 305)
        ]
