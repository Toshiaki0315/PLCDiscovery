"""
Regressions from the remaining findings of the second code review:
configuration and CLI, discovery, output and notifications, simulators and
the protocol handlers.
"""

import asyncio
import logging
import struct
from unittest.mock import MagicMock

import pytest

from plc_discovery import settings_file
from plc_discovery.broadcast_discovery import BroadcastDiscovery
from plc_discovery.cli_args import resolve_device_ranges_only
from plc_discovery.config import DataPoint, DeviceRange, DeviceType, NetworkConfig, PLCInfo, Protocol, StatusCode
from plc_discovery.config_loader import ConfigLoader
from plc_discovery.database import DatabaseExporter
from plc_discovery.discovery import PLCDiscovery, plc_key
from plc_discovery.output import CSVExporter
from plc_discovery.progress import create_progress_callback
from plc_discovery.protocols.ethernet_ip import EtherNetIPHandler
from plc_discovery.protocols.fins import FINSHandler
from plc_discovery.thresholds import Threshold, ThresholdMonitor
from plc_discovery.utils import ip_range_error, parse_ip_range, target_address_error

# ----------------------------------------------------------------------
# Configuration and CLI
# ----------------------------------------------------------------------


def _loader_with_ranges():
    loader = ConfigLoader()
    loader.config["scan"]["device_ranges"] = [{"device": "D", "start": 0, "end": 10}]
    return loader


def test_device_option_without_range_is_not_ignored():
    def ranges(device, range_text=None):
        args = MagicMock(device=device, range=range_text)
        return [(r.device_type, r.start_address, r.end_address) for r in resolve_device_ranges_only(args, loader)]

    loader = _loader_with_ranges()
    assert ranges("W") == [(DeviceType.W, 0, 999)]
    assert ranges(None) == [(DeviceType.D, 0, 10)]  # no option: the config file's ranges
    assert ranges("W", "5-9") == [(DeviceType.W, 5, 9)]
    assert ranges(None, "5-9") == [(DeviceType.D, 5, 9)]


def test_config_validation_of_filters_limits_and_output():
    loader = ConfigLoader()
    loader.config["discovery"]["protocols"] = []
    loader._file_config = {"discovery": {"protocols": []}}
    loader.config["network"]["max_concurrent"] = 100000
    loader.config["output"]["encoding"] = "euc-jp"
    loader.config["output"]["directory"] = 5
    errors = "\n".join(loader.validate())
    for fragment in ("discovery.protocols", "network.max_concurrent", "output.encoding", "output.directory"):
        assert fragment in errors


def test_unknown_config_keys_are_reported(caplog):
    loader = ConfigLoader()
    loader.config["output"]["directry"] = "./x"
    loader.config["scna"] = {}
    with caplog.at_level(logging.WARNING):
        assert loader.validate() == []
    assert "output.directry" in caplog.text and "scna" in caplog.text


def test_settings_file_name_must_be_readable_by_the_cli(tmp_path):
    path = tmp_path / "plc.conf"
    _, errors = settings_file.save(str(path), {"network": {"packet_interval_ms": 100}})
    assert errors and not path.exists()


# ----------------------------------------------------------------------
# Discovery
# ----------------------------------------------------------------------


def test_broadcast_only_slmp_result_says_the_tcp_port_is_unverified():
    plc = BroadcastDiscovery()._parse_slmp_response("10.0.0.5", b"\xd0\x00" + b"\x00" * 12)
    assert plc is not None and "未確認" in (plc.model or "")


def test_mac_maker_replaces_the_name_the_protocol_implies(monkeypatch):
    discovery = PLCDiscovery(NetworkConfig())
    implied = PLCInfo("10.0.0.1", protocol=Protocol.SLMP, port=5001, manufacturer="三菱電機/キーエンス")
    identified = PLCInfo("10.0.0.2", protocol=Protocol.MODBUS_TCP, port=502, manufacturer="Yokogawa")
    for plc in (implied, identified):
        discovery.discovered_plcs[plc_key(plc)] = plc
    monkeypatch.setattr(
        "plc_discovery.discovery.read_arp_cache",
        lambda: {"10.0.0.1": "00:01:FC:00:00:01", "10.0.0.2": "00:01:FC:00:00:02"},  # Keyence OUI
    )
    asyncio.run(discovery._fill_macs_from_arp_cache())
    assert implied.manufacturer == "キーエンス"
    assert identified.manufacturer == "Yokogawa"  # what the device itself reported stays


@pytest.mark.parametrize("text", ["224.0.0.0/30", "0.0.0.0/24", "255.255.255.255", "224.0.0.1-5", "0.0.0.0"])
def test_ranges_that_are_not_device_addresses_are_rejected(text):
    assert ip_range_error(text)  # what --ip-range and the config file report
    assert parse_ip_range(text) == []
    assert ip_range_error("192.168.1.0/24") is None and len(parse_ip_range("192.168.1.0/24")) == 254


def test_target_must_be_a_device_address():
    assert target_address_error("224.0.0.1") and target_address_error("255.255.255.255")
    assert target_address_error("192.168.1.10") is None and target_address_error("simulators") is None


# ----------------------------------------------------------------------
# Output and notifications
# ----------------------------------------------------------------------


def test_size_limit_deletes_data_points_before_history(tmp_path):
    db = DatabaseExporter.create(str(tmp_path / "plc.db"))
    for cycle in range(30):
        points = [DataPoint(address=f"D{i}", value=cycle * 1000 + i, status=StatusCode.OK) for i in range(200)]
        db.export_plc_data(points, "10.0.0.1", protocol="SLMP", port=5001)
    count = lambda table: db._db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # noqa: E731
    history_before, points_before = count("data_history"), count("data_points")
    assert history_before > 0

    db.config.max_size_mb = db.used_bytes() * 0.8 / (1024 * 1024)
    assert db._enforce_size_limit() > 0
    assert count("data_points") < points_before
    assert count("data_history") == history_before  # untouched while data points could go
    db.close()


def test_empty_denied_log_gets_its_header(tmp_path):
    exporter = CSVExporter(str(tmp_path), "utf-8")
    (tmp_path / "access_denied_log.csv").write_bytes(b"")
    path = exporter.export_denied_addresses({"D100"}, "10.0.0.1")
    lines = open(path, encoding="utf-8").read().splitlines()
    assert lines[0].startswith("address") and "D100" in lines[1]


def test_progress_callback_updates_the_first_task():
    display = MagicMock()
    create_progress_callback(display, 0)("reading", 3, 10)  # rich's first task id is 0
    display._progress.update.assert_called_once_with(0, completed=3, total=10, description="reading")


def test_waiting_threshold_notification_goes_out_while_the_value_is_not_read():
    monitor = ThresholdMonitor([Threshold("D1", ">", 10)])
    ok = [DataPoint(address="D1", status=StatusCode.OK, value=20)]
    ng = [DataPoint(address="D1", status=StatusCode.NG_TIMEOUT)]

    # Exceeded, but the notification is throttled
    assert monitor.evaluate("PLC1", ok, lambda t, kind: False).exceeded == []
    # Next cycles: the address times out; the notification may go out now
    check = monitor.evaluate("PLC1", ng, lambda t, kind: True)
    assert [(e.threshold.address, e.value) for e in check.exceeded] == [("D1", 20.0)]
    assert monitor.evaluate("PLC1", ng, lambda t, kind: True).exceeded == []  # once
    # An address never read has nothing to report
    assert ThresholdMonitor([Threshold("D1", ">", 10)]).evaluate("PLC1", ng).exceeded == []


# ----------------------------------------------------------------------
# Simulators
# ----------------------------------------------------------------------


def test_simulator_tag_write_must_fit_the_tag_type():
    from simulators.control import write_value

    device = MagicMock()
    device.logix_tags = {"Counter": ("INT", 0), "Total": ("DINT", 0)}
    with pytest.raises(ValueError, match="does not fit"):
        write_value("logix", device, "", "Counter", 100000)
    write_value("logix", device, "", "Total", 100000)
    assert device.logix_tags["Total"] == ("DINT", 100000) and device.logix_tags["Counter"] == ("INT", 0)


def test_s7_simulator_refuses_reads_past_the_end_of_a_db():
    from simulators.s7_simulator import S7_RET_ADDRESS_OUT_OF_RANGE, S7_RET_OK, S7Device

    device = S7Device()
    assert device.read_db(1, 1990, 10)[1] == S7_RET_OK
    assert device.read_db(1, 1990, 12) == (None, S7_RET_ADDRESS_OUT_OF_RANGE)
    device.data_blocks[1][2500] = 1  # a value written further out extends the block
    assert device.read_db(1, 2490, 11)[1] == S7_RET_OK


def test_eip_simulator_requires_a_registered_session():
    from simulators.ethernet_ip_simulator import (
        EIP_CMD_REGISTER_SESSION,
        EIP_CMD_SEND_RR_DATA,
        EtherNetIPDevice,
        EtherNetIPProtocol,
    )

    protocol = EtherNetIPProtocol(EtherNetIPDevice())
    status = lambda reply: struct.unpack("<I", reply[8:12])[0]  # noqa: E731

    reply = protocol._process_command(EIP_CMD_SEND_RR_DATA, 0x1234, b"\x00" * 8, b"\x00" * 16)
    assert status(reply) == 0x0064  # invalid session handle

    registered = protocol._process_command(EIP_CMD_REGISTER_SESSION, 0, b"\x00" * 8, struct.pack("<HH", 1, 0))
    session = struct.unpack("<I", registered[4:8])[0]
    reply = protocol._process_command(EIP_CMD_SEND_RR_DATA, session, b"\x00" * 8, b"\x00" * 16)
    assert status(reply) != 0x0064


def test_simulator_reports_a_port_it_cannot_use(caplog):
    from simulators.common import run_simulator

    async def server():
        raise PermissionError(13, "Permission denied")

    with caplog.at_level(logging.ERROR), pytest.raises(SystemExit) as exit_info:
        run_simulator(server(), logging.getLogger("simulator-test"))
    assert exit_info.value.code == 1 and "--port" in caplog.text


# ----------------------------------------------------------------------
# Protocol handlers
# ----------------------------------------------------------------------


def test_fins_does_not_read_index_registers_as_words():
    handler = FINSHandler("192.168.1.10", config=NetworkConfig(packet_interval_ms=0))
    handler._connected = True
    data, status = asyncio.run(handler.read_device_raw(DeviceType.IR, 0, 4))
    assert (data, status) == (None, StatusCode.NG_UNSUPPORTED)


def test_full_scan_reads_the_first_element_of_multi_dimensional_arrays():
    handler = EtherNetIPHandler("127.0.0.1")
    handler._plc_type = "logix"
    handler._client = MagicMock(
        tags={
            "Grid": {"tag_type": "atomic", "dimensions": [4, 5, 0]},
            "Row": {"tag_type": "atomic", "dimensions": [8, 0, 0]},
            "Speed": {"tag_type": "atomic", "dimensions": [0, 0, 0]},
        }
    )
    assert handler.tag_scan_list() == ["Grid[0,0]", "Row[0]{8}", "Speed"]


def test_modbus_full_scan_ranges_still_use_input_registers():
    # IR stays a Modbus device (input registers); only FINS dropped it
    from plc_discovery.config import DEFAULT_DEVICE_RANGES

    assert DeviceRange(DeviceType.IR, 0, 9999) in DEFAULT_DEVICE_RANGES[Protocol.MODBUS_TCP]
    assert all(r.device_type != DeviceType.IR for r in DEFAULT_DEVICE_RANGES[Protocol.FINS])
