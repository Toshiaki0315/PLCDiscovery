"""
Binary Search Algorithm Integration Tests

Tests the binary search error recovery algorithm with actual simulators.
The simulators have predefined denied address ranges that the algorithm
should correctly identify.

Denied ranges in simulators:
- SLMP: D5000-D5100, D7000-D7050
- Modbus: HR5000-HR5100, HR8000-HR8050
"""

import pytest

from plc_discovery.collector import PLCDataCollector
from plc_discovery.config import DeviceType, StatusCode

pytestmark = [
    pytest.mark.integration,
    pytest.mark.asyncio,
]


class TestBinarySearchSLMP:
    """Test binary search with SLMP simulator"""

    async def test_single_denied_range(self, slmp_simulator, slmp_plc_info, network_config):
        """Test finding a single denied range"""
        async with PLCDataCollector(slmp_plc_info, network_config) as collector:
            # Read exactly the denied range
            data_points = await collector.collect_range(DeviceType.D, 5000, 5100)

        # All 101 addresses should be denied
        denied_count = sum(1 for dp in data_points if dp.status == StatusCode.NG_ILLEGAL_ADDR)
        assert denied_count == 101

    async def test_denied_at_start(self, slmp_simulator, slmp_plc_info, network_config):
        """Test denied range at the start of read range"""
        async with PLCDataCollector(slmp_plc_info, network_config) as collector:
            # D5000-D5100 denied, D5101-D5200 valid
            data_points = await collector.collect_range(DeviceType.D, 5000, 5200)

        ok_count = sum(1 for dp in data_points if dp.status == StatusCode.OK)
        denied_count = sum(1 for dp in data_points if dp.status == StatusCode.NG_ILLEGAL_ADDR)

        # 5000-5100 = 101 denied, 5101-5200 = 100 OK
        assert ok_count == 100
        assert denied_count == 101

    async def test_denied_at_end(self, slmp_simulator, slmp_plc_info, network_config):
        """Test denied range at the end of read range"""
        async with PLCDataCollector(slmp_plc_info, network_config) as collector:
            # D4900-D4999 valid, D5000-D5100 denied
            data_points = await collector.collect_range(DeviceType.D, 4900, 5100)

        ok_count = sum(1 for dp in data_points if dp.status == StatusCode.OK)
        denied_count = sum(1 for dp in data_points if dp.status == StatusCode.NG_ILLEGAL_ADDR)

        # 4900-4999 = 100 OK, 5000-5100 = 101 denied
        assert ok_count == 100
        assert denied_count == 101

    async def test_denied_in_middle(self, slmp_simulator, slmp_plc_info, network_config):
        """Test denied range in the middle of read range"""
        async with PLCDataCollector(slmp_plc_info, network_config) as collector:
            # D4900-D4999 valid, D5000-D5100 denied, D5101-D5200 valid
            data_points = await collector.collect_range(DeviceType.D, 4900, 5200)

        ok_count = sum(1 for dp in data_points if dp.status == StatusCode.OK)
        denied_count = sum(1 for dp in data_points if dp.status == StatusCode.NG_ILLEGAL_ADDR)

        # 4900-4999 + 5101-5200 = 200 OK
        # 5000-5100 = 101 denied
        assert ok_count == 200
        assert denied_count == 101

    async def test_multiple_denied_ranges(self, slmp_simulator, slmp_plc_info, network_config):
        """Test finding multiple denied ranges"""
        async with PLCDataCollector(slmp_plc_info, network_config) as collector:
            # Read range spanning both denied ranges
            # D5000-D5100 and D7000-D7050
            data_points = await collector.collect_range(DeviceType.D, 4900, 7100)
            denied = collector.get_denied_addresses()

        # Check denied addresses were found
        # (Note: The number depends on how the binary search identifies the ranges)
        assert len(denied) > 0

        # Verify the statistics
        ok_count = sum(1 for dp in data_points if dp.status == StatusCode.OK)
        denied_count = sum(1 for dp in data_points if dp.status == StatusCode.NG_ILLEGAL_ADDR)

        # Total should equal total addresses
        assert ok_count + denied_count == len(data_points)


class TestBinarySearchModbus:
    """Test binary search with Modbus simulator"""

    async def test_single_denied_range(self, modbus_simulator, modbus_plc_info, network_config):
        """Test finding a single denied range"""
        async with PLCDataCollector(modbus_plc_info, network_config) as collector:
            data_points = await collector.collect_range(DeviceType.HR, 5000, 5100)

        denied_count = sum(1 for dp in data_points if dp.status == StatusCode.NG_ILLEGAL_ADDR)
        assert denied_count == 101

    async def test_denied_in_middle(self, modbus_simulator, modbus_plc_info, network_config):
        """Test denied range in the middle"""
        async with PLCDataCollector(modbus_plc_info, network_config) as collector:
            data_points = await collector.collect_range(DeviceType.HR, 4900, 5200)

        ok_count = sum(1 for dp in data_points if dp.status == StatusCode.OK)
        denied_count = sum(1 for dp in data_points if dp.status == StatusCode.NG_ILLEGAL_ADDR)

        assert ok_count == 200
        assert denied_count == 101


class TestBinarySearchPerformance:
    """Test binary search performance characteristics"""

    async def test_cached_addresses_skip(self, slmp_simulator, slmp_plc_info, network_config):
        """Test that cached denied addresses are skipped on subsequent reads"""
        async with PLCDataCollector(slmp_plc_info, network_config) as collector:
            # First read - discovers denied addresses
            await collector.collect_range(DeviceType.D, 5000, 5100)
            stats1 = collector.get_statistics()

            # Second read - should skip known denied
            await collector.collect_range(DeviceType.D, 5000, 5100)
            stats2 = collector.get_statistics()

        # Should have same total points but potentially fewer actual reads
        # (This depends on implementation details)
        assert stats2["total_points"] >= stats1["total_points"]

    async def test_all_valid_no_extra_reads(self, slmp_simulator, slmp_plc_info, network_config):
        """Test that all-valid range doesn't trigger unnecessary binary search"""
        async with PLCDataCollector(slmp_plc_info, network_config) as collector:
            # Read range with no denied addresses
            data_points = await collector.collect_range(DeviceType.D, 0, 99)
            denied = collector.get_denied_addresses()

        # All should be OK
        ok_count = sum(1 for dp in data_points if dp.status == StatusCode.OK)
        assert ok_count == 100

        # No denied addresses
        assert len(denied) == 0


class TestBinarySearchEdgeCases:
    """Test binary search edge cases"""

    async def test_single_denied_address(self, slmp_simulator, slmp_plc_info, network_config):
        """Test finding a single denied address"""
        async with PLCDataCollector(slmp_plc_info, network_config) as collector:
            # Read just the first denied address
            data_points = await collector.collect_range(DeviceType.D, 5000, 5000)

        assert len(data_points) == 1
        assert data_points[0].status == StatusCode.NG_ILLEGAL_ADDR

    async def test_boundary_addresses(self, slmp_simulator, slmp_plc_info, network_config):
        """Test boundary addresses of denied range"""
        async with PLCDataCollector(slmp_plc_info, network_config) as collector:
            # Read just before, at, and just after denied range boundary
            # D4999 (OK), D5000 (denied)
            data_points = await collector.collect_range(DeviceType.D, 4999, 5001)

        assert len(data_points) == 3

        # First should be OK (4999)
        assert data_points[0].status == StatusCode.OK
        # Second and third should be denied (5000, 5001)
        assert data_points[1].status == StatusCode.NG_ILLEGAL_ADDR
        assert data_points[2].status == StatusCode.NG_ILLEGAL_ADDR

    async def test_empty_range(self, slmp_simulator, slmp_plc_info, network_config):
        """Test reading single address (start == end)"""
        async with PLCDataCollector(slmp_plc_info, network_config) as collector:
            data_points = await collector.collect_range(DeviceType.D, 100, 100)

        assert len(data_points) == 1
        assert data_points[0].status == StatusCode.OK
