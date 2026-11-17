"""
EtherNet/IP Logix integration tests: the simulator in Logix mode answers
pycomm3's LogixDriver (identity, program name, tag list, Read Tag,
multiple service and fragmented reads), read through the tool's
EtherNetIPHandler / PLCDataCollector.
"""

import pytest

from plc_discovery.collector import PLCDataCollector
from plc_discovery.config import DeviceType, StatusCode

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


async def test_connects_with_logix_driver(logix_simulator, logix_plc_info, network_config):
    async with PLCDataCollector(logix_plc_info, network_config) as collector:
        assert collector._handler.is_connected
        assert collector._handler.supports_tags


async def test_read_tags(logix_simulator, logix_plc_info, network_config):
    async with PLCDataCollector(logix_plc_info, network_config) as collector:
        points = await collector.collect_tags(["Speed", "Temp", "Running", "Counter", "Recipe[2]{3}", "Nope"])
    by_address = {p.address: p for p in points}
    assert by_address["Speed"].value == 1500
    assert by_address["Temp"].converted_value == pytest.approx(23.5)
    assert by_address["Running"].value == 1
    assert by_address["Counter"].value == 42
    assert [by_address[f"Recipe[{i}]"].value for i in (2, 3, 4)] == [20, 30, 40]
    assert by_address["Nope"].status == StatusCode.NG_ILLEGAL_ADDR


async def test_fragmented_array_read(logix_simulator, logix_plc_info, network_config):
    """600 INT elements do not fit one reply: pycomm3 reads them in fragments"""
    async with PLCDataCollector(logix_plc_info, network_config) as collector:
        points = await collector.collect_tags(["Trend[0]{600}"])
    assert len(points) == 600
    assert all(p.status == StatusCode.OK for p in points)
    assert points[-1].address == "Trend[599]" and points[-1].value == 599


async def test_full_scan_reads_every_tag(logix_simulator, logix_plc_info, network_config):
    async with PLCDataCollector(logix_plc_info, network_config) as collector:
        points = await collector.collect_full_scan()
    # Speed, Temp, Running, Counter, Recipe[10], Trend[600], Motor (3 members),
    # Program:MainProgram.Step / .Setpoint
    assert len(points) == 4 + 10 + 600 + 3 + 2
    assert all(p.status == StatusCode.OK for p in points)
    addresses = {p.address for p in points}
    assert {"Motor.Speed", "Program:MainProgram.Step"} <= addresses


async def test_struct_tag_flattened(logix_simulator, logix_plc_info, network_config):
    """A UDT tag is read whole (pycomm3 reads the template) and reported per member"""
    async with PLCDataCollector(logix_plc_info, network_config) as collector:
        points = await collector.collect_tags(["Motor", "Motor.Current"])
    values = {p.address: p.converted_value if p.data_type == "REAL" else p.value for p in points}
    assert values == {"Motor.Speed": 1200, "Motor.Current": pytest.approx(3.5), "Motor.Count": 7}
    assert len(points) == 4  # Motor.Current twice


async def test_program_scope_tags(logix_simulator, logix_plc_info, network_config):
    async with PLCDataCollector(logix_plc_info, network_config) as collector:
        points = await collector.collect_tags(["Program:MainProgram.Step", "Program:MainProgram.Nope"])
    assert (points[0].address, points[0].value) == ("Program:MainProgram.Step", 3)
    assert points[1].status == StatusCode.NG_ILLEGAL_ADDR


async def test_address_reads_unsupported_on_logix(logix_simulator, logix_plc_info, network_config):
    """Logix has no numeric data files: address reads stay NG_UNSUPPORTED"""
    async with PLCDataCollector(logix_plc_info, network_config) as collector:
        points = await collector.collect_range(DeviceType.D, 0, 9)
    assert {p.status for p in points} == {StatusCode.NG_UNSUPPORTED}
