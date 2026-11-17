"""
Regression tests for the thirteenth review's findings.

D1: the MAC OUI table names the companies the IEEE registered the OUIs to.
D2: the report lists failed targets (with the reason) and output errors.
"""

import json
from unittest.mock import AsyncMock, patch

import pytest

import plc_scanner
from plc_discovery.config import MANUFACTURER_OUI, DataPoint, StatusCode
from plc_discovery.report import create_report
from plc_discovery.utils import get_manufacturer_from_mac

# ---------------------------------------------------------------------------
# D1: OUI table
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "mac, maker",
    [
        ("00:00:0A:01:02:03", "オムロン"),
        ("00:01:FC:01:02:03", "キーエンス"),
        ("00:26:92:01:02:03", "三菱電機"),
        ("00:00:64:01:02:03", "横河電機"),
        ("00:00:BC:01:02:03", "ロックウェル"),
        ("00:0E:8C:01:02:03", "シーメンス"),  # previously "ロックウェル"
        ("00:40:1A:01:02:03", "富士電機"),
        ("00:20:B5:01:02:03", "安川電機"),
    ],
)
def test_real_vendor_ouis_are_recognised(mac, maker):
    assert get_manufacturer_from_mac(mac) == maker


@pytest.mark.parametrize(
    "mac",
    [
        "00:10:FA:01:02:03",  # Apple (was "富士電機")
        "00:0A:DC:01:02:03",  # RuggedCom switch (was "オムロン")
        "00:00:1C:01:02:03",  # Bell Technologies (was "三菱電機")
        "00:0D:7C:01:02:03",  # Codian (was "キーエンス")
        "00:30:11:01:02:03",  # HMS (was "東芝")
        "00:60:52:01:02:03",  # Peripherals Enterprise (was "安川電機")
    ],
)
def test_other_companies_ouis_are_not_named_as_plc_makers(mac):
    assert get_manufacturer_from_mac(mac) is None


def test_oui_keys_are_normalised():
    for oui in MANUFACTURER_OUI:
        assert oui == oui.upper() and len(oui) == 8 and oui.count(":") == 2


def test_oui_matches_wireshark_database():
    try:
        from scapy.all import conf
    except Exception:
        pytest.skip("scapy not installed")
    if not getattr(conf, "manufdb", None):
        pytest.skip("scapy has no manuf database")
    keywords = {
        "オムロン": "omron",
        "キーエンス": "keyence",
        "三菱電機": "mitsubishi",
        "横河電機": "yokogawa",
        "ロックウェル": "rockwell",
        "シーメンス": "siemens",
        "富士電機": "fuji electric",
        "安川電機": "yaskawa",
        "日立産機": "hitachi",
        "ジェイテクト": "jtekt",
        "IDEC": "idec",
        "デルタ電子": "delta",
        "シュナイダー": "schneider",
        "東芝": "toshiba",
        "パナソニック": "panasonic",
    }
    for oui, maker in MANUFACTURER_OUI.items():
        registered = conf.manufdb._get_manuf(oui + ":00:00:00")
        assert keywords[maker] in registered.lower(), (oui, maker, registered)


# ---------------------------------------------------------------------------
# D2: errors in the report
# ---------------------------------------------------------------------------


def test_create_report_keeps_errors():
    _, data = create_report(plcs=[], data_points={}, errors=["10.0.0.2: refused"])
    assert data.errors == ["10.0.0.2: refused"]
    _, data = create_report(plcs=[], data_points={})
    assert data.errors == []


@pytest.mark.asyncio
async def test_cli_report_lists_failed_targets(tmp_path, monkeypatch):
    async def scan(plc_info, *a, **k):
        if plc_info.ip_address == "10.0.0.2":
            return plc_scanner.ScanOutcome("10.0.0.2", error="Failed to connect to 10.0.0.2:5001 (SLMP): refused")
        return plc_scanner.ScanOutcome(
            plc_info.ip_address, success=True, data_points=[DataPoint("D0", 1, "0x0001", StatusCode.OK)]
        )

    monkeypatch.setattr(
        "sys.argv",
        [
            "plc_scanner.py",
            "--mode",
            "range",
            "--target",
            "10.0.0.1,10.0.0.2",
            "--protocol",
            "slmp",
            "--device",
            "D",
            "--range",
            "0-0",
            "--output-dir",
            str(tmp_path),
            "--report",
            "json",
            "--report-output",
            str(tmp_path / "report.json"),
        ],
    )
    with patch.object(plc_scanner, "run_single_scan", AsyncMock(side_effect=scan)):
        with pytest.raises(SystemExit) as exit_info:
            await plc_scanner.main()
    assert exit_info.value.code == 1

    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert report["errors"] == ["10.0.0.2: Failed to connect to 10.0.0.2:5001 (SLMP): refused"]


def test_target_error_without_reason():
    assert plc_scanner._target_error("10.0.0.3", None) == "10.0.0.3: scan failed"
