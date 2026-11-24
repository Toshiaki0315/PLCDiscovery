"""
Regressions from the third code review (low findings):
- hex of tag values: 8-bit types, structure members typed from the
  controller's structure definitions
- audit console output never fails the operation being recorded
- the GUI worker stays busy until the GUI has handled a job's result
- the large-scan estimate includes the packet interval between batches
"""

import asyncio
import sys
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from plc_discovery import discovery
from plc_discovery.audit_log import AuditLogger
from plc_discovery.config import NetworkConfig
from plc_discovery.discovery import LARGE_SCAN_WARNING_HOSTS, PLCDiscovery
from plc_discovery.protocols.ethernet_ip import _tag_hex, _tag_points, _value_points

# ----------------------------------------------------------------------
# Hex of tag values
# ----------------------------------------------------------------------

DEFINITIONS = {
    "Recipe": {
        "internal_tags": {
            "Count": {"data_type_name": "DINT"},
            "Flags": {"data_type_name": "SINT"},
            "Limits": {"data_type_name": "Limit"},
            "Steps": {"data_type_name": "INT"},
        }
    },
    "Limit": {"internal_tags": {"Low": {"data_type_name": "INT"}, "High": {"data_type_name": "LINT"}}},
}


@pytest.mark.parametrize(
    "value, type_name, expected",
    [(-1, "SINT", "0xFF"), (200, "USINT", "0xC8"), (0x7F, "BYTE", "0x7F"), (1, "BOOL", "0x01"), (-1, "INT", "0xFFFF")],
)
def test_eight_bit_types_are_two_hex_digits(value, type_name, expected):
    assert _tag_hex(value, type_name) == expected


def test_structure_members_use_the_types_of_the_structure_definition():
    value = {"Count": -1, "Flags": -1, "Limits": {"Low": -2, "High": 5}, "Steps": [1, -1]}
    points = {p.address: p.raw_hex for p in _value_points("R1", value, "Recipe", DEFINITIONS)}
    assert points == {
        "R1.Count": "0xFFFFFFFF",  # DINT, not 0xFFFF
        "R1.Flags": "0xFF",
        "R1.Limits.Low": "0xFFFE",
        "R1.Limits.High": "0x0000000000000005",
        "R1.Steps[0]": "0x0001",
        "R1.Steps[1]": "0xFFFF",
    }


def test_array_of_structures_and_reply_type_with_dimension():
    reply = MagicMock(error=None, value=[{"Low": -1, "High": -1}, {"Low": 3, "High": 4}], type="Limit[2]")
    points = {p.address: p.raw_hex for p in _tag_points("Lim[0]{2}", reply, DEFINITIONS)}
    assert points["Lim[0].Low"] == "0xFFFF" and points["Lim[0].High"] == "0xFFFFFFFFFFFFFFFF"
    assert points["Lim[1].Low"] == "0x0003"


def test_members_without_a_definition_fall_back_to_the_value_width():
    for definitions in (None, {}, {"Recipe": {}}, {"Recipe": {"internal_tags": {"Count": {}}}}):
        points = _value_points("R1", {"Count": -1, "Big": 70000}, "Recipe", definitions)
        assert [(p.address, p.raw_hex) for p in points] == [("R1.Count", "0xFFFF"), ("R1.Big", "0x00011170")]


# ----------------------------------------------------------------------
# Audit console output
# ----------------------------------------------------------------------


def test_audit_console_output_failure_does_not_reach_the_caller(tmp_path):
    log = tmp_path / "audit.jsonl"
    audit = AuditLogger(str(log), console_output=True)
    try:
        with patch("builtins.print", side_effect=UnicodeEncodeError("cp932", "タグ", 0, 1, "illegal")):
            audit.log_tag_read("10.0.0.1", "ETHERNET_IP", ["温度"], "OK", 1.0)  # must not raise
    finally:
        audit.close()
    assert "温度" in log.read_text(encoding="utf-8")  # the file record is written all the same


# ----------------------------------------------------------------------
# GUI worker
# ----------------------------------------------------------------------


def _import_async_worker(monkeypatch):
    try:
        import tkinter  # noqa: F401
    except ImportError:
        tk = MagicMock()
        monkeypatch.setitem(sys.modules, "tkinter", tk)
        for name in ("filedialog", "messagebox", "ttk"):
            monkeypatch.setitem(sys.modules, f"tkinter.{name}", getattr(tk, name))
        monkeypatch.delitem(sys.modules, "plc_gui", raising=False)
    from plc_gui import AsyncWorker

    return AsyncWorker


def _wait(condition, seconds=5.0):
    deadline = time.monotonic() + seconds
    while not condition() and time.monotonic() < deadline:
        time.sleep(0.005)
    return condition()


def test_gui_worker_stays_busy_until_the_result_is_acknowledged(monkeypatch):
    worker = _import_async_worker(monkeypatch)(acknowledge=True)
    done = []

    async def job():
        return None

    try:
        worker.submit(job(), done.append)
        assert _wait(lambda: len(done) == 1)
        # Ended, but the GUI has not handled the result yet: no new job
        assert worker.busy
        worker.acknowledge()
        assert not worker.busy
        # The next job follows the same rule
        worker.submit(job(), done.append)
        assert _wait(lambda: len(done) == 2) and worker.busy
        worker.acknowledge()
        assert not worker.busy
    finally:
        worker.shutdown(timeout=2)


def test_gui_worker_without_acknowledge_is_free_when_the_job_ends(monkeypatch):
    worker = _import_async_worker(monkeypatch)()
    done = []

    async def job():
        return None

    try:
        worker.submit(job(), done.append)
        assert _wait(lambda: len(done) == 1) and _wait(lambda: not worker.busy)
    finally:
        worker.shutdown(timeout=2)


# ----------------------------------------------------------------------
# Large-scan estimate
# ----------------------------------------------------------------------


def test_large_scan_estimate_includes_the_packet_interval(caplog):
    hosts = [f"10.0.{i // 250}.{i % 250 + 1}" for i in range(LARGE_SCAN_WARNING_HOSTS + 500)]
    config = NetworkConfig(discovery_timeout_ms=1000, packet_interval_ms=1000, max_concurrent=1)
    scanner = PLCDiscovery(config)

    async def run():
        with (
            patch.object(scanner, "_probe_host_all", AsyncMock(return_value=[])),
            patch.object(discovery.asyncio, "sleep", AsyncMock()),
        ):
            await scanner._probe_hosts(hosts, {})

    with caplog.at_level("WARNING"):
        asyncio.run(run())
    batches = len(hosts) / 10
    expected_minutes = batches * (2 * 1.0 + 1.0) / 60  # two timeouts and one interval per batch
    assert f"~{expected_minutes:.0f} minutes" in caplog.text
