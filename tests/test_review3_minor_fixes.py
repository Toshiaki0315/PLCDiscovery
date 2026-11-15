"""
Regression tests for the third review's minor findings.
"""

import json
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import plc_scanner
from plc_discovery.collector import PLCDataCollector
from plc_discovery.config import DataPoint, NetworkConfig, PLCInfo, Protocol, StatusCode
from plc_discovery.config_loader import ConfigLoader
from plc_discovery.discovery import PLCDiscovery
from plc_discovery.output import CSVExporter
from plc_discovery.protocols.fins import FINSHandler
from plc_discovery.report import ReportConfig, ReportFormat, create_report


def load(tmp_path, data):
    path = tmp_path / "c.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    loader = ConfigLoader(str(path))
    loader.load()
    return loader


# ---------------------------------------------------------------------------
# 1: config validation
# ---------------------------------------------------------------------------

class TestConfigValidation:

    def test_unknown_target_protocol(self, tmp_path):
        loader = load(tmp_path, {"targets": [{"ip": "10.0.0.1", "protocol": "fins_tpc"}]})
        assert any("unknown protocol 'fins_tpc'" in e for e in loader.validate())

    def test_unknown_discovery_protocol(self, tmp_path):
        loader = load(tmp_path, {"discovery": {"protocols": ["slmp", "modbuss"]}})
        assert any("modbuss" in e for e in loader.validate())

    def test_target_options(self, tmp_path):
        good = load(tmp_path, {"targets": [
            {"ip": "10.0.0.1", "protocol": "fins", "options": {"dest_node": 5}},
            {"ip": "10.0.0.2", "protocol": "s7", "options": {"rack": 0, "slot": 1, "db_number": 10}},
        ]})
        assert good.validate() == []
        assert good.get_targets()[1].options == {"rack": 0, "slot": 1, "db_number": 10}
        bad = load(tmp_path, {"targets": [{"ip": "10.0.0.1", "protocol": "modbus", "options": {"slot": 1}}]})
        assert any("slot not supported for MODBUS_TCP" in e for e in bad.validate())

    def test_options_reach_the_handler(self):
        plc = PLCInfo("127.0.0.1", protocol=Protocol.S7, port=102, options={"db_number": 7, "slot": 1})
        collector = PLCDataCollector(plc)
        with patch("plc_discovery.protocols.s7.S7Handler.connect", AsyncMock(return_value=True)):
            import asyncio
            assert asyncio.run(collector.connect())
        assert collector._handler._db_number == 7 and collector._handler._slot == 1


# ---------------------------------------------------------------------------
# 2: periodic interval minimum and unique file names
# ---------------------------------------------------------------------------

def test_cli_rejects_sub_second_interval(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", [
        "plc_scanner.py", "--mode", "range", "--target", "127.0.0.1", "--interval", "0.5",
    ])
    with pytest.raises(SystemExit) as exc:
        plc_scanner.cli()
    assert exc.value.code == 1
    assert ">= 1 seconds" in capsys.readouterr().out


def test_config_rejects_sub_second_interval(tmp_path):
    loader = load(tmp_path, {"scan": {"interval_seconds": 0.2}})
    assert any("interval_seconds" in e for e in loader.validate())


def test_same_second_exports_do_not_overwrite(tmp_path):
    exporter = CSVExporter(str(tmp_path))
    points = [DataPoint("D0", 1, "0x0001", StatusCode.OK)]
    with patch("plc_discovery.output.get_file_timestamp", return_value="20260101_000000"):
        paths = [exporter.export_plc_data(points, "10.0.0.1") for _ in range(3)]
    assert len(set(paths)) == 3
    assert paths[1].endswith("plc_data_10_0_0_1_20260101_000000_1.csv")


# ---------------------------------------------------------------------------
# 3: FINS node addresses
# ---------------------------------------------------------------------------

class TestFINSNodes:

    def test_dest_node_defaults_to_last_octet(self):
        assert FINSHandler("192.168.1.40").dest_node == 40
        assert FINSHandler("192.168.1.40", dest_node=3).dest_node == 3

    def test_invalid_node_rejected(self):
        with pytest.raises(ValueError):
            FINSHandler("192.168.1.40", source_node=300)

    def test_tcp_handshake_requests_explicit_client_node(self):
        assert FINSHandler("10.0.0.1", use_tcp=True)._build_tcp_handshake()[-4:] == b"\x00\x00\x00\x00"
        assert FINSHandler("10.0.0.1", use_tcp=True, source_node=7)._build_tcp_handshake()[-4:] == b"\x00\x00\x00\x07"

    @pytest.mark.asyncio
    async def test_udp_source_node_from_local_address(self):
        handler = FINSHandler("127.0.0.1", 9, config=NetworkConfig(request_timeout_ms=200))
        frames = []

        async def fake_send(frame, sid):
            frames.append(frame)
            return None   # no PLC: connect fails after building the frame

        handler._send_udp = fake_send
        assert await handler.connect() is False
        assert handler.source_node == 1                      # 127.0.0.1 -> node 1
        assert frames[0][4] == 1 and frames[0][7] == 1       # DA1, SA1 in the frame


# ---------------------------------------------------------------------------
# 4-6: discovery details
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_discovery_protocol_filter():
    discovery = PLCDiscovery(NetworkConfig(discovery_timeout_ms=100), protocols=[Protocol.MODBUS_TCP])
    probed = []
    with patch("plc_discovery.discovery.is_port_open", side_effect=lambda ip, p, t: probed.append(p) or False), \
            patch("plc_discovery.discovery.verify_protocol", side_effect=AssertionError("not expected")):
        assert await discovery._probe_host("192.0.2.1") is None
    assert probed == [502]   # no SLMP/S7/EIP checks and no FINS/UDP probe


def test_discovery_protocols_from_cli_and_config(tmp_path, monkeypatch):
    args = MagicMock(discover_protocols="eip, fins-tcp")
    assert plc_scanner.resolve_discovery_protocols(args, None) == [Protocol.ETHERNET_IP, Protocol.FINS_TCP]
    args = MagicMock(discover_protocols=None)
    assert plc_scanner.resolve_discovery_protocols(args, load(tmp_path, {})) is None   # default: all
    loader = load(tmp_path, {"discovery": {"protocols": ["slmp", "fins_tcp"]}})
    assert plc_scanner.resolve_discovery_protocols(args, loader) == [Protocol.SLMP, Protocol.FINS_TCP]
    with pytest.raises(ValueError):
        plc_scanner.resolve_discovery_protocols(MagicMock(discover_protocols="bogus"), None)


@pytest.mark.asyncio
async def test_modbus_identity_keeps_existing_manufacturer():
    discovery = PLCDiscovery(NetworkConfig())
    plc = PLCInfo("127.0.0.1", protocol=Protocol.MODBUS_TCP, port=502, manufacturer="横河電機")
    response = MagicMock()
    response.isError.return_value = False
    response.information = {0: b"", 1: b"FA-M3", 2: b""}
    client = MagicMock()
    client.connect.return_value = True
    client.read_device_information.return_value = response
    with patch("pymodbus.client.ModbusTcpClient", return_value=client):
        result = await discovery._query_modbus_info(plc)
    assert result.manufacturer == "横河電機"
    assert result.model == "FA-M3"


# ---------------------------------------------------------------------------
# 7: periodic report labelled as last cycle
# ---------------------------------------------------------------------------

def test_report_escapes_and_shows_mode(tmp_path):
    config = ReportConfig(format=ReportFormat.HTML, output_path=str(tmp_path))
    generator, data = create_report([], {}, {}, "range (periodic every 60s, last cycle) <b>", None, None, config)
    html = generator.generate(data)
    assert "periodic every 60s, last cycle" in html
    assert "<b>" not in html.split("periodic every 60s, last cycle")[1][:10]


# ---------------------------------------------------------------------------
# Example config (empty YAML sections load as None)
# ---------------------------------------------------------------------------

def test_shipped_example_config_is_valid():
    from pathlib import Path
    loader = ConfigLoader(str(Path(__file__).resolve().parent.parent / "plc_config.example.yaml"))
    loader.load()
    assert loader.validate() == []
    assert loader.get_targets() == []


def test_empty_yaml_section_keeps_default(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text("targets:\n  # none yet\nscan:\n  device_ranges:\n", encoding="utf-8")
    loader = ConfigLoader(str(path))
    loader.load()
    assert loader.validate() == []
    assert loader.get_targets() == [] and loader.get_device_ranges() == []
