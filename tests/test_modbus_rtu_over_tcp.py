"""
Modbus RTU over TCP (targets[].options.rtu): RTU frames - unit, PDU and
CRC16, no MBAP header - on the TCP connection, for serial-to-Ethernet
converters that pass the bytes through to an RTU device.
"""

import asyncio
import struct
from unittest.mock import MagicMock, patch

import pytest

from plc_discovery.collector import PLCDataCollector
from plc_discovery.config import (
    DataPoint,
    DeviceRange,
    DeviceType,
    NetworkConfig,
    PLCInfo,
    Protocol,
    StatusCode,
    protocol_label,
)
from plc_discovery.config_loader import ConfigLoader
from plc_discovery.database import DatabaseConfig, DatabaseExporter
from plc_discovery.discovery import target_labels
from plc_discovery.output import CSVExporter
from plc_discovery.protocols.modbus import ModbusHandler, modbus_framer_kwargs
from plc_discovery.scan_runner import ResultWriter
from simulators.modbus_simulator import ModbusDevice, ModbusProtocol, ModbusRTUProtocol, crc16_modbus

FAST_500MS = NetworkConfig(packet_interval_ms=0, retry_interval_ms=0, request_timeout_ms=500)


def _rtu(frame_hex: str) -> bytes:
    """An RTU frame with its CRC (low byte first)"""
    frame = bytes.fromhex(frame_hex)
    return frame + struct.pack("<H", crc16_modbus(frame))


# Handler -------------------------------------------------------------------


@pytest.mark.parametrize("rtu, framer", [(1, "rtu"), (0, "socket")])
def test_rtu_option_selects_the_rtu_framer(rtu, framer):
    created = {}

    class Client:
        def __init__(self, **kwargs):
            created.update(kwargs)

        def connect(self):
            return True

    handler = ModbusHandler("192.168.0.10", rtu=rtu, config=FAST_500MS)
    with patch("pymodbus.client.ModbusTcpClient", Client):
        assert asyncio.run(handler.connect()) is True
    # Modbus/TCP: pymodbus' default (socket framer, MBAP header)
    assert created.get("framer", "socket") == framer
    assert created["retries"] == 0  # retries stay with BaseProtocolHandler


def test_rtu_option_reaches_the_handler_from_the_target_options():
    plc = PLCInfo("192.168.0.10", protocol=Protocol.MODBUS_TCP, port=502, options={"unit_id": 3, "rtu": 1})
    collector = PLCDataCollector(plc, FAST_500MS)
    with patch.object(ModbusHandler, "connect", return_value=True):
        assert asyncio.run(collector.connect()) is True
    handler = collector._handler
    assert isinstance(handler, ModbusHandler) and handler._rtu is True and handler._unit_id == 3


def test_pymodbus_without_rtu_framing_is_a_clear_connection_failure(caplog):
    handler = ModbusHandler("192.168.0.10", rtu=1, config=FAST_500MS)
    with patch("plc_discovery.protocols.modbus.modbus_framer_kwargs", side_effect=ImportError("FramerType")):
        assert asyncio.run(handler.connect()) is False
    assert "pymodbus 3.7 or later" in caplog.text


def test_modbus_tcp_needs_no_framer_argument():
    # Works with every pymodbus 3.x: nothing is imported for Modbus/TCP
    assert modbus_framer_kwargs(False) == {}


@pytest.mark.parametrize("value, ok", [(1, True), (0, True), (2, False), ("yes", False)])
def test_rtu_is_a_valid_modbus_target_option(value, ok):
    loader = ConfigLoader()
    loader.config["targets"] = [{"ip": "10.0.0.1", "protocol": "modbus", "options": {"rtu": value}}]
    errors = loader.validate()
    assert (errors == []) is ok
    if not ok:
        assert any("rtu" in e for e in errors)


def test_rtu_is_no_option_of_other_protocols():
    loader = ConfigLoader()
    loader.config["targets"] = [{"ip": "10.0.0.1", "protocol": "slmp", "options": {"rtu": 1}}]
    assert any("rtu" in e for e in loader.validate())


# Simulator -----------------------------------------------------------------


def test_crc16_of_a_known_frame():
    # Read 10 holding registers from 0 of unit 1: CRC C5 CD on the wire
    assert _rtu("01030000000A")[-2:] == bytes.fromhex("C5CD")


class _Transport:
    def __init__(self):
        self.written = []

    def write(self, data):
        self.written.append(data)


def _simulator():
    protocol = ModbusRTUProtocol(ModbusDevice([(5000, 5100)]))
    protocol.transport = _Transport()
    return protocol


def test_simulator_answers_an_rtu_frame_with_unit_pdu_and_crc():
    protocol = _simulator()
    protocol.data_received(_rtu("07030000" "0002"))  # unit 7, HR0 x2
    (answer,) = protocol.transport.written
    assert answer == _rtu("070304" "0000" "0005")  # registers 0 and 5 (address * 5)


def test_simulator_reports_an_invalid_address_with_an_exception_frame():
    protocol = _simulator()
    protocol.data_received(_rtu("01031388" "0001"))  # HR5000: denied
    assert protocol.transport.written == [_rtu("0183" "02")]


def test_simulator_joins_a_frame_sent_in_pieces_and_splits_two_in_one():
    protocol = _simulator()
    frame = _rtu("01030000" "0001")
    protocol.data_received(frame[:3])
    assert protocol.transport.written == []
    protocol.data_received(frame[3:] + _rtu("01030001" "0001"))
    assert protocol.transport.written == [_rtu("010302" "0000"), _rtu("010302" "0005")]


def test_simulator_does_not_answer_a_frame_with_a_wrong_crc():
    protocol = _simulator()
    frame = bytearray(_rtu("01030000" "0001"))
    frame[-1] ^= 0xFF
    protocol.data_received(bytes(frame))
    assert protocol.transport.written == []
    # More than a frame of garbage is dropped: the next valid frame is answered
    protocol.data_received(bytes(300))
    assert protocol.buffer == b""
    protocol.data_received(_rtu("01030000" "0001"))
    assert protocol.transport.written == [_rtu("010302" "0000")]


# Handler and simulator over TCP --------------------------------------------


async def _serve(protocol_class):
    device = ModbusDevice([(5000, 5100)])
    server = await asyncio.get_running_loop().create_server(lambda: protocol_class(device), "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


@pytest.mark.asyncio
async def test_rtu_handler_reads_an_rtu_device():
    server, port = await _serve(ModbusRTUProtocol)
    try:
        handler = ModbusHandler("127.0.0.1", port, unit_id=3, rtu=1, config=FAST_500MS)
        assert await handler.connect()
        assert await handler.read_device_raw(DeviceType.HR, 0, 5) == ([0, 5, 10, 15, 20], StatusCode.OK)
        assert await handler.read_device_raw(DeviceType.M, 0, 4) == ([1, 0, 1, 0], StatusCode.OK)
        # The binary search finds where the invalid registers start
        points = await handler.read_device_range(DeviceRange(DeviceType.HR, 4995, 5004))
        assert [p.status for p in points] == [StatusCode.OK] * 5 + [StatusCode.NG_ILLEGAL_ADDR] * 5
        await handler.disconnect()
    finally:
        server.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("server_class, rtu", [(ModbusRTUProtocol, 0), (ModbusProtocol, 1)])
async def test_framing_that_does_not_match_the_device_is_not_answered(server_class, rtu):
    """A Modbus/TCP request to an RTU device (or the reverse) gets no valid answer"""
    server, port = await _serve(server_class)
    try:
        handler = ModbusHandler("127.0.0.1", port, rtu=rtu, config=FAST_500MS)
        assert await handler.connect()
        data, status = await handler.read_device_raw(DeviceType.HR, 0, 1)
        assert data is None and status in (StatusCode.NG_TIMEOUT, StatusCode.NG_COMM_ERROR)
        await handler.disconnect()
    finally:
        server.close()


def test_simulator_command_line_has_the_rtu_switch(monkeypatch):
    import simulators.modbus_simulator as simulator

    started = MagicMock()
    monkeypatch.setattr(simulator, "run_simulator", lambda coroutine, logger: started(coroutine))
    monkeypatch.setattr(simulator, "run_server", lambda host, port, denied, rtu=False: ("run", port, rtu))
    monkeypatch.setattr("sys.argv", ["modbus_simulator.py", "--port", "1503", "--rtu"])
    simulator.main()
    started.assert_called_once_with(("run", 1503, True))


# The name written out -------------------------------------------------------


def _rtu_target(rtu=1, port=502):
    return PLCInfo("192.168.1.50", protocol=Protocol.MODBUS_TCP, port=port, options={"unit_id": 3, "rtu": rtu})


@pytest.mark.parametrize(
    "protocol, options, label",
    [
        (Protocol.MODBUS_TCP, {"rtu": 1}, "MODBUS_RTU_OVER_TCP"),
        (Protocol.MODBUS_TCP, {"rtu": 0}, "MODBUS_TCP"),
        (Protocol.MODBUS_TCP, {}, "MODBUS_TCP"),
        (Protocol.MODBUS_TCP, None, "MODBUS_TCP"),
        (Protocol.SLMP, {"rtu": 1}, "SLMP"),  # a Modbus option only
        (None, {"rtu": 1}, None),
    ],
)
def test_protocol_label(protocol, options, label):
    assert protocol_label(protocol, options) == label


def test_rtu_target_is_named_apart_in_the_labels_and_the_discovery_row():
    rtu, tcp = _rtu_target(rtu=1), _rtu_target(rtu=0, port=503)
    assert target_labels([rtu, tcp]) == ["192.168.1.50 (MODBUS_RTU_OVER_TCP:502)", "192.168.1.50 (MODBUS_TCP:503)"]
    assert rtu.to_dict()["protocol"] == "MODBUS_RTU_OVER_TCP"
    assert tcp.to_dict()["protocol"] == "MODBUS_TCP"


def test_rtu_target_is_named_apart_in_the_file_name_and_the_database(tmp_path):
    rtu, tcp = _rtu_target(rtu=1), _rtu_target(rtu=0, port=503)
    db = DatabaseExporter(DatabaseConfig(enabled=True, path=str(tmp_path / "plc.db"), track_history=False))
    db.export_discovery_results([rtu, tcp])
    point = DataPoint(address="HR0", value=1, raw_hex="0x0001", status=StatusCode.OK, timestamp="2026-11-26 10:00:00")
    for plc, label in zip([rtu, tcp], target_labels([rtu, tcp])):
        writer = ResultWriter(plc, CSVExporter(str(tmp_path)), db_exporter=db, label=label)
        assert writer.export_points([point])
    names = sorted(path.name for path in tmp_path.glob("plc_data_*.csv"))
    assert [name.split("_2026")[0].rsplit("_", 1)[0] for name in names] == [
        "plc_data_192_168_1_50_MODBUS_RTU_OVER_TCP",
        "plc_data_192_168_1_50_MODBUS_TCP",
    ]
    rows = db._connection.execute("SELECT protocol, port FROM data_points ORDER BY port").fetchall()
    assert [tuple(row) for row in rows] == [("MODBUS_RTU_OVER_TCP", 502), ("MODBUS_TCP", 503)]
    plcs = db._connection.execute("SELECT protocol, port FROM plcs ORDER BY port").fetchall()
    assert [tuple(row) for row in plcs] == [("MODBUS_RTU_OVER_TCP", 502), ("MODBUS_TCP", 503)]
    db.close()


def test_audit_log_names_the_rtu_framing():
    assert ModbusHandler("192.168.1.50", rtu=1, config=FAST_500MS).protocol_label == "MODBUS_RTU_OVER_TCP"
    assert ModbusHandler("192.168.1.50", config=FAST_500MS).protocol_label == "MODBUS_TCP"
