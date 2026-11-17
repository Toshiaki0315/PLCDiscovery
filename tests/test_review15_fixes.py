"""
Regression tests for the security review (fifteenth review).

S1: text reported by devices cannot drive the operator's terminal
    (control characters removed, Rich markup shown literally).
S2: the HTML report loads no external scripts (inline SVG charts) and
    escapes the logo path.
S3: user-specified IP ranges are limited to MAX_IP_RANGE_HOSTS.
S4: simulators listen on 127.0.0.1 unless told otherwise.
"""

import ast
import io
import json
import struct
from pathlib import Path

import pytest

import plc_scanner
from plc_discovery.config import DataPoint, PLCInfo, Protocol, StatusCode, clean_device_text
from plc_discovery.config_loader import ConfigLoader
from plc_discovery.probes import parse_eip_identity
from plc_discovery.report import ReportConfig, ReportGenerator, create_report
from plc_discovery.utils import MAX_IP_RANGE_HOSTS, ip_range_error, parse_ip_range

ROOT = Path(__file__).resolve().parent.parent
EVIL = "m\x1b]0;pwned\x07\x1b[2J\x9b31m"


# ---------------------------------------------------------------------------
# S1: device text and the terminal
# ---------------------------------------------------------------------------


def test_clean_device_text():
    assert clean_device_text(EVIL) == "m]0;pwned[2J31m"
    assert clean_device_text(" NJ501\r\n") == "NJ501"
    assert clean_device_text(None) is None


def test_plcinfo_strips_control_characters_however_set():
    plc = PLCInfo("10.0.0.1", model=EVIL, manufacturer="A\x1bB")
    plc.cpu_type = "C\x07PU"
    plc.firmware_version = "1.0\x00"
    assert (plc.model, plc.manufacturer, plc.cpu_type, plc.firmware_version) == ("m]0;pwned[2J31m", "AB", "CPU", "1.0")
    assert "\x1b" not in json.dumps(plc.to_dict())


def test_eip_identity_product_name_cleaned():
    name = b"KV\x1b[2J-8000"
    body = struct.pack("<HHHBBHI", 367, 0x0E, 1, 1, 2, 0, 1) + bytes([len(name)]) + name + b"\x03"
    item = struct.pack("<H", 1) + b"\x00" * 16 + body
    reply = (
        struct.pack("<HHII", 0x63, 2 + 4 + len(item), 0, 0)
        + b"\x00" * 8
        + struct.pack("<I", 0)
        + struct.pack("<HHH", 1, 0x0C, len(item))
        + item
    )
    assert parse_eip_identity(reply)["product_name"] == "KV[2J-8000"


def _rich_display():
    from rich.console import Console

    from plc_discovery.progress import RichProgressDisplay

    display = RichProgressDisplay()
    buffer = io.StringIO()
    display.console = Console(file=buffer, force_terminal=True, width=200)
    return display, buffer


def test_discovery_table_shows_markup_literally_without_escapes():
    pytest.importorskip("rich")
    display, buffer = _rich_display()
    display.print_discovery_results(
        [
            {
                "ip_address": "10.0.0.1",
                "protocol": "EIP",
                "port": 44818,
                "manufacturer": "[link=http://evil.example]click[/link]",
                "model": EVIL,
            }
        ]
    )
    out = buffer.getvalue()
    assert "\x1b]8;" not in out  # no hyperlink (previously injected)
    assert "\x1b]0;" not in out and "\x1b[2J" not in out and "\x07" not in out
    assert "[link=http://evil.example]click[/link]" in out


def test_messages_strip_control_characters():
    pytest.importorskip("rich")
    display, buffer = _rich_display()
    display.print_error(f"Detected {EVIL}")
    display.print(f"value {EVIL}")
    out = buffer.getvalue()
    assert "\x1b]0;" not in out and "\x1b[2J" not in out and "\x9b" not in out


def test_plain_output_strips_control_characters(capsys):
    from plc_discovery.progress import RichProgressDisplay

    display = RichProgressDisplay(use_rich=False)
    display.print_discovery_results([{"ip_address": "10.0.0.1", "protocol": "EIP", "manufacturer": EVIL}])
    display.print_warning(EVIL)
    assert "\x1b" not in capsys.readouterr().out


# ---------------------------------------------------------------------------
# S2: report has no external scripts
# ---------------------------------------------------------------------------


def _report(**config):
    plcs = [PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001)]
    points = {
        "10.0.0.1": [
            DataPoint("D0", 1, "0x0001", StatusCode.OK),
            DataPoint("D1", None, None, StatusCode.NG_ILLEGAL_ADDR),
        ]
    }
    generator, data = create_report(plcs=plcs, data_points=points, config=ReportConfig(**config))
    return generator.generate(data)


def test_html_report_has_no_external_scripts():
    html = _report()
    assert "<script" not in html.lower()  # previously Chart.js from cdn.jsdelivr.net
    assert "cdn." not in html and "https://" not in html
    assert html.count("<svg") == 2 and "statusChart" in html and "plcChart" in html


def test_html_report_without_charts_has_no_svg():
    assert "<svg" not in _report(include_charts=False)


def test_logo_path_and_language_are_escaped(tmp_path):
    logo = tmp_path / 'logo"onerror="alert(1).png'
    logo.write_bytes(b"x")
    html = _report(logo_path=str(logo), language='ja" onload="x')
    assert 'onerror="alert(1)' not in html and 'onload="x' not in html
    assert "&quot;onerror=&quot;" in html


def test_svg_chart_escapes_labels():
    generator = ReportGenerator(ReportConfig())
    _, data = create_report(plcs=[], data_points={"<b>x</b>": [DataPoint("D0", 1, "0x0001", StatusCode.OK)]})
    assert "<b>x</b>" not in generator.generate(data).split("plcChart")[1].split("</svg>")[0]


# ---------------------------------------------------------------------------
# S3: IP range size limit
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ip_range, ok",
    [
        ("192.168.1.0/24", True),
        ("10.0.0.0/16", True),  # 65,534 hosts
        ("10.0.0.0/15", False),
        ("10.0.0.0/8", False),  # 16.7 million hosts (a /24 typo)
        ("10.0.0.0-10.1.0.0", False),  # 65,537 hosts
        ("10.0.0.1-10.0.255.255", True),
        ("192.168.1.5", True),
        ("192.168.1.0/33", False),
    ],
)
def test_ip_range_error(ip_range, ok):
    assert (ip_range_error(ip_range) is None) is ok


def test_parse_ip_range_refuses_huge_range():
    assert parse_ip_range("10.0.0.0/8") == []
    assert len(parse_ip_range("10.0.0.0/16")) == 65534
    assert parse_ip_range("10.0.0.0/31") == ["10.0.0.0", "10.0.0.1"]


def test_config_validate_rejects_huge_range(tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"discovery": {"ip_ranges": ["192.168.1.0/24", "10.0.0.0/8"]}}))
    loader = ConfigLoader(str(path))
    loader.load()
    errors = loader.validate()
    assert len(errors) == 1 and errors[0].startswith("discovery.ip_ranges[1]:")
    assert f"{MAX_IP_RANGE_HOSTS:,}" in errors[0]


def test_cli_rejects_huge_range_before_scanning(tmp_path, monkeypatch, capsys):
    import asyncio
    from unittest.mock import AsyncMock, patch

    monkeypatch.setattr(
        "sys.argv", ["plc_scanner.py", "--mode", "discover", "--ip-range", "10.0.0.0/8", "-o", str(tmp_path)]
    )
    probe = AsyncMock(return_value=[])
    with patch.object(plc_scanner, "discover_plcs", probe), pytest.raises(SystemExit) as exit_info:
        asyncio.run(plc_scanner.main())
    assert exit_info.value.code == 1
    probe.assert_not_called()
    assert "16,777,214 hosts" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# S4: simulators listen on loopback by default
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["slmp", "modbus", "ethernet_ip", "s7", "fins", "run_all"])
def test_simulator_default_host_is_loopback(name):
    filename = "run_all.py" if name == "run_all" else f"{name}_simulator.py"
    tree = ast.parse((ROOT / "simulators" / filename).read_text(encoding="utf-8"))
    defaults = [
        kw.value.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        for kw in node.keywords
        if kw.arg == "default"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == "--host"
    ]
    assert defaults == ["127.0.0.1"]


def test_simulator_classes_default_to_loopback():
    from simulators.fins_simulator import FINSSimulator
    from simulators.run_all import SimulatorManager

    assert FINSSimulator().host == "127.0.0.1"
    assert SimulatorManager().host == "127.0.0.1"


def test_docker_simulators_listen_in_container_published_on_loopback():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert 'CMD ["python", "simulators/run_all.py", "--host", "0.0.0.0"]' in dockerfile
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert '"5001:5001"' not in compose and '"127.0.0.1:5001:5001"' in compose


# ---------------------------------------------------------------------------
# Codex review: scan.mode typo, VACUUM in cleanup
# ---------------------------------------------------------------------------


def _loader(tmp_path, config):
    path = tmp_path / "c.json"
    path.write_text(json.dumps(config))
    loader = ConfigLoader(str(path))
    loader.load()
    return loader


@pytest.mark.parametrize("mode", ["rang", "fulll", "scan"])
def test_unknown_scan_mode_is_config_error(tmp_path, mode):
    loader = _loader(tmp_path, {"scan": {"mode": mode}})
    assert any(e.startswith("scan.mode: unknown mode") for e in loader.validate())
    from plc_discovery.config import ScanMode

    assert loader.get_scan_mode() == ScanMode.DISCOVER  # previously FULL


@pytest.mark.parametrize("mode", ["range", "RANGE", " full ", "discover"])
def test_known_scan_modes_accepted(tmp_path, mode):
    assert _loader(tmp_path, {"scan": {"mode": mode}}).validate() == []


def test_cli_scan_mode_typo_exits_without_scanning(tmp_path, monkeypatch, capsys):
    import asyncio
    from unittest.mock import AsyncMock, patch

    path = tmp_path / "c.json"
    path.write_text(json.dumps({"scan": {"mode": "rang"}, "targets": [{"ip": "127.0.0.1", "protocol": "slmp"}]}))
    monkeypatch.setattr("sys.argv", ["plc_scanner.py", "--config", str(path), "-o", str(tmp_path)])
    scan = AsyncMock()
    with patch.object(plc_scanner, "run_single_scan", scan), pytest.raises(SystemExit) as exit_info:
        asyncio.run(plc_scanner.main())
    assert exit_info.value.code == 1
    scan.assert_not_called()
    assert "scan.mode: unknown mode 'rang'" in capsys.readouterr().out


def test_cleanup_old_data_vacuums(tmp_path):
    from plc_discovery.database import DatabaseConfig, DatabaseExporter

    db = DatabaseExporter(DatabaseConfig(enabled=True, path=str(tmp_path / "d.db")))
    db.export_plc_data([DataPoint("D0", 1, "0x0001", StatusCode.OK)], "10.0.0.1")
    db._connection.execute("UPDATE data_points SET timestamp = '2000-01-01T00:00:00'")
    db.export_plc_data([DataPoint("D0", 2, "0x0002", StatusCode.OK)], "10.0.0.1")
    db._connection.commit()
    db.cleanup_old_data(30)  # previously OperationalError: cannot VACUUM from within a transaction
    rows = db._connection.execute("SELECT value FROM data_points").fetchall()
    assert [r[0] for r in rows] == [2]
    db.close()


# ---------------------------------------------------------------------------
# External review: SLMP broadcast subheaders, discovery SLMP connection
# ---------------------------------------------------------------------------


def test_slmp_broadcast_request_matches_probe_frame():
    from plc_discovery.broadcast_discovery import BroadcastDiscovery

    request = BroadcastDiscovery()._build_slmp_discovery_request()
    assert request[:2] == b"\x50\x00"  # previously b"\x00\x50"
    # same 3E "Read Type Name" frame as the TCP probe
    assert request == bytes.fromhex("5000" "00ff" "ff03" "00" "0600" "1000" "0101" "0000")


def test_slmp_broadcast_accepts_real_reply_and_rejects_reversed_bytes():
    from plc_discovery.broadcast_discovery import BroadcastDiscovery

    discovery = BroadcastDiscovery()
    reply = b"\xd0\x00\x00\xff\xff\x03\x00\x02\x00\x00\x00"  # 3E response, end code 0
    plc = discovery._parse_slmp_response("10.0.0.5", reply)
    assert plc is not None and plc.protocol == Protocol.SLMP  # previously None
    assert discovery._parse_slmp_response("10.0.0.5", b"\x00\xd0" + reply[2:]) is None


def test_slmp_broadcast_end_to_end_with_udp_responder():
    """A UDP responder that answers only well-formed 3E requests"""
    import asyncio
    import socket
    from unittest.mock import patch

    from plc_discovery.broadcast_discovery import BroadcastDiscovery

    responder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    responder.bind(("127.0.0.1", 0))
    responder.settimeout(3)
    port = responder.getsockname()[1]

    def serve():
        data, addr = responder.recvfrom(1024)
        if data[:2] == b"\x50\x00":
            responder.sendto(b"\xd0\x00\x00\xff\xff\x03\x00\x02\x00\x00\x00", addr)

    async def run():
        import threading

        threading.Thread(target=serve, daemon=True).start()
        from plc_discovery.config import NetworkConfig

        discovery = BroadcastDiscovery(NetworkConfig(discovery_timeout_ms=500))
        # a /32 "network": its directed broadcast address is 127.0.0.1 itself
        with (
            patch("plc_discovery.broadcast_discovery.SLMP_DISCOVERY_PORT", port),
            patch(
                "plc_discovery.broadcast_discovery.get_local_networks", return_value=[("127.0.0.1", "255.255.255.255")]
            ),
        ):
            return await discovery.discover_slmp_broadcast()

    try:
        plcs = asyncio.run(run())
    finally:
        responder.close()
    assert [p.ip_address for p in plcs] == ["127.0.0.1"]


@pytest.mark.asyncio
async def test_discovery_slmp_info_opens_no_connection():
    from unittest.mock import patch

    from plc_discovery.config import NetworkConfig
    from plc_discovery.discovery import PLCDiscovery

    plc = PLCInfo("10.0.0.5", protocol=Protocol.SLMP, port=5001)
    with (
        patch("socket.socket.connect", side_effect=AssertionError("connected")),
        patch("socket.create_connection", side_effect=AssertionError("connected")),
    ):
        result = await PLCDiscovery(NetworkConfig())._query_slmp_info(plc)
    assert (result.manufacturer, result.model) == ("三菱電機/キーエンス", "SLMP対応PLC")
    keyence = PLCInfo("10.0.0.6", protocol=Protocol.SLMP, port=5001, manufacturer="キーエンス")
    assert (await PLCDiscovery(NetworkConfig())._query_slmp_info(keyence)).manufacturer == "キーエンス"
