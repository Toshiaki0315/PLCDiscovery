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
    assert (plc.model, plc.manufacturer, plc.cpu_type, plc.firmware_version) == (
        "m]0;pwned[2J31m", "AB", "CPU", "1.0")
    assert "\x1b" not in json.dumps(plc.to_dict())


def test_eip_identity_product_name_cleaned():
    name = b"KV\x1b[2J-8000"
    body = struct.pack("<HHHBBHI", 367, 0x0E, 1, 1, 2, 0, 1) + bytes([len(name)]) + name + b"\x03"
    item = struct.pack("<H", 1) + b"\x00" * 16 + body
    reply = (struct.pack("<HHII", 0x63, 2 + 4 + len(item), 0, 0) + b"\x00" * 8 + struct.pack("<I", 0)
             + struct.pack("<HHH", 1, 0x0C, len(item)) + item)
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
    display.print_discovery_results([{
        "ip_address": "10.0.0.1", "protocol": "EIP", "port": 44818,
        "manufacturer": "[link=http://evil.example]click[/link]", "model": EVIL,
    }])
    out = buffer.getvalue()
    assert "\x1b]8;" not in out          # no hyperlink (previously injected)
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
    points = {"10.0.0.1": [DataPoint("D0", 1, "0x0001", StatusCode.OK),
                           DataPoint("D1", None, None, StatusCode.NG_ILLEGAL_ADDR)]}
    generator, data = create_report(plcs=plcs, data_points=points, config=ReportConfig(**config))
    return generator.generate(data)


def test_html_report_has_no_external_scripts():
    html = _report()
    assert "<script" not in html.lower()      # previously Chart.js from cdn.jsdelivr.net
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

@pytest.mark.parametrize("ip_range, ok", [
    ("192.168.1.0/24", True),
    ("10.0.0.0/16", True),                       # 65,534 hosts
    ("10.0.0.0/15", False),
    ("10.0.0.0/8", False),                       # 16.7 million hosts (a /24 typo)
    ("10.0.0.0-10.1.0.0", False),                # 65,537 hosts
    ("10.0.0.1-10.0.255.255", True),
    ("192.168.1.5", True),
    ("192.168.1.0/33", False),
])
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
    monkeypatch.setattr("sys.argv", ["plc_scanner.py", "--mode", "discover",
                                     "--ip-range", "10.0.0.0/8", "-o", str(tmp_path)])
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
        kw.value.value for node in ast.walk(tree) if isinstance(node, ast.Call)
        for kw in node.keywords if kw.arg == "default"
        and node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value == "--host"
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
