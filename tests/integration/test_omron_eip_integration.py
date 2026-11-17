"""
Omron NJ/NX integration tests: the EtherNet/IP simulator in Omron mode has
no Logix tag list / program name (pycomm3's LogixDriver cannot connect, as
with a real NJ/NX). The tool falls back to a generic CIP connection and reads
variables by name with raw Read Tag requests.
"""

import pytest

from plc_discovery.collector import PLCDataCollector
from plc_discovery.config import DeviceType, StatusCode

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


async def test_connects_as_generic_cip_with_tag_support(omron_simulator, omron_plc_info, network_config):
    async with PLCDataCollector(omron_plc_info, network_config) as collector:
        assert collector._handler._plc_type == "generic"
        assert collector._handler.supports_tags
        assert collector._handler.tag_scan_list() == []        # no tag list on NJ/NX


async def test_read_variables_by_name(omron_simulator, omron_plc_info, network_config):
    async with PLCDataCollector(omron_plc_info, network_config) as collector:
        points = await collector.collect_tags([
            "Temperature", "Pressure", "TotalCount", "StatusWord", "Values[2]{3}",
            "Motor.Speed", "Motor.Current", "Motor", "Nope", "Values[30]"])
    by_address = {p.address: p for p in points}
    assert by_address["Temperature"].converted_value == pytest.approx(25.5)
    assert by_address["Pressure"].converted_value == pytest.approx(0.101325)
    assert by_address["TotalCount"].value == 123456
    assert by_address["StatusWord"].raw_hex == "0x00FF"
    assert [by_address[f"Values[{i}]"].value for i in (2, 3, 4)] == [4, 6, 8]
    assert by_address["Motor.Speed"].value == 900
    assert by_address["Motor.Current"].converted_value == pytest.approx(2.5)
    # A whole structure has no layout without a tag list: read members by name
    assert by_address["Motor"].status == StatusCode.NG_UNSUPPORTED
    assert by_address["Nope"].status == StatusCode.NG_ILLEGAL_ADDR
    assert by_address["Values[30]"].status == StatusCode.NG_ILLEGAL_ADDR


async def test_large_array_fragmented(omron_simulator, omron_plc_info, network_config):
    """300 DINT (1200 bytes) do not fit one reply: Read Tag Fragmented continues at an offset"""
    async with PLCDataCollector(omron_plc_info, network_config) as collector:
        points = await collector.collect_tags(["History[0]{300}"])
    assert [p.value for p in points] == list(range(300))
    assert points[-1].address == "History[299]"


async def test_address_reads_unsupported(omron_simulator, omron_plc_info, network_config):
    """NJ/NX variables have no numeric addresses over EtherNet/IP (use FINS for DM)"""
    async with PLCDataCollector(omron_plc_info, network_config) as collector:
        points = await collector.collect_range(DeviceType.D, 0, 9)
    assert {p.status for p in points} == {StatusCode.NG_UNSUPPORTED}
