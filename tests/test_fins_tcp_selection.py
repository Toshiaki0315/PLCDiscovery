"""
Unit tests for selecting FINS/TCP (Protocol.FINS_TCP) from CLI, config and
discovery.
"""

import json
import socket
import sys
import threading
from unittest.mock import patch

import pytest

import plc_scanner
from plc_discovery.collector import PROTOCOL_HANDLERS
from plc_discovery.config import (
    DEFAULT_DEVICE_RANGES, PROTOCOL_PORTS, SAFE_READ_WORDS, NetworkConfig, Protocol
)
from plc_discovery.config_loader import ConfigLoader
from plc_discovery.discovery import PLCDiscovery
from plc_discovery.probes import UDP_PROTOCOLS, probe_fins_udp
from plc_discovery.protocols.fins import FINSHandler


def test_fins_tcp_protocol_defaults():
    assert PROTOCOL_PORTS[Protocol.FINS_TCP] == 9600
    assert SAFE_READ_WORDS[Protocol.FINS_TCP] == SAFE_READ_WORDS[Protocol.FINS]
    assert DEFAULT_DEVICE_RANGES[Protocol.FINS_TCP] == DEFAULT_DEVICE_RANGES[Protocol.FINS]


def test_handler_factory_selects_transport():
    udp = PROTOCOL_HANDLERS[Protocol.FINS]("127.0.0.1", port=9600, config=NetworkConfig())
    tcp = PROTOCOL_HANDLERS[Protocol.FINS_TCP]("127.0.0.1", port=9600, config=NetworkConfig())
    assert isinstance(udp, FINSHandler) and udp.use_tcp is False
    assert isinstance(tcp, FINSHandler) and tcp.use_tcp is True
    assert tcp.protocol == Protocol.FINS_TCP
    assert tcp.max_read_size == 400


def test_cli_protocol_option(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["plc_scanner.py", "--protocol", "fins-tcp"])
    args = plc_scanner.parse_args()
    assert plc_scanner.get_protocol_from_string(args.protocol) == Protocol.FINS_TCP
    assert plc_scanner.get_protocol_from_string("fins") == Protocol.FINS


@pytest.mark.parametrize("name, expected", [
    ("fins", Protocol.FINS),
    ("fins_udp", Protocol.FINS),
    ("fins_tcp", Protocol.FINS_TCP),
    ("FINS-TCP", Protocol.FINS_TCP),
])
def test_config_protocol_names(tmp_path, name, expected):
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"targets": [{"ip": "10.0.0.1", "protocol": name}]}))
    loader = ConfigLoader(str(path))
    loader.load()
    assert loader.get_targets()[0].protocol == expected


# ---------------------------------------------------------------------------
# Discovery: FINS/UDP is probed over UDP, FINS/TCP over TCP
# ---------------------------------------------------------------------------

def fins_reply(req: bytes) -> bytes:
    header = bytes([0xC0, 0x00, 0x02, req[6], req[7], req[8], req[3], req[4], req[5], req[9]])
    return header + req[10:12] + b"\x00\x00\x00\x00"


class UDPResponder:
    def __init__(self, respond):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.1)
        self.port = self.sock.getsockname()[1]
        self.respond = respond
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        while not self.stop.is_set():
            try:
                data, addr = self.sock.recvfrom(2048)
            except OSError:
                continue
            reply = self.respond(data)
            if reply:
                self.sock.sendto(reply, addr)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.stop.set()
        self.thread.join(1)
        self.sock.close()


class TestFINSUDPProbe:

    def test_matching_reply(self):
        with UDPResponder(fins_reply) as srv:
            assert probe_fins_udp("127.0.0.1", srv.port, 1.0)

    def test_wrong_sid_rejected(self):
        def wrong_sid(req):
            reply = bytearray(fins_reply(req))
            reply[9] = (reply[9] + 1) & 0xFF
            return bytes(reply)
        with UDPResponder(wrong_sid) as srv:
            assert not probe_fins_udp("127.0.0.1", srv.port, 0.5)

    def test_no_reply(self):
        with UDPResponder(lambda req: None) as srv:
            assert not probe_fins_udp("127.0.0.1", srv.port, 0.3)


@pytest.mark.asyncio
async def test_discovery_probes_fins_udp_without_tcp_port():
    """FINS/UDP must be detected even though TCP 9600 is closed"""
    assert Protocol.FINS in UDP_PROTOCOLS and Protocol.FINS_TCP not in UDP_PROTOCOLS
    discovery = PLCDiscovery(NetworkConfig(discovery_timeout_ms=200))
    checked = []

    def verify(ip, port, protocol, timeout):
        checked.append(protocol)
        return protocol == Protocol.FINS

    with patch("plc_discovery.discovery.is_port_open", return_value=False), \
            patch("plc_discovery.discovery.verify_protocol", side_effect=verify), \
            patch.object(discovery, "_get_detailed_info", side_effect=lambda plc: plc):
        result = await discovery._probe_host("192.0.2.40")

    assert checked == [Protocol.FINS]    # TCP protocols skipped (ports closed)
    assert result.protocol == Protocol.FINS and result.port == 9600
