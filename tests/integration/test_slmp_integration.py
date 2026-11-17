"""
SLMP Integration Tests

Tests actual communication with SLMP simulator.
"""

import pytest

from plc_discovery.collector import PLCDataCollector
from plc_discovery.config import DeviceRange, DeviceType, PLCInfo, Protocol, StatusCode

# Mark all tests to require SLMP simulator
pytestmark = [
    pytest.mark.integration,
    pytest.mark.asyncio,
]


class TestSLMPConnection:
    """Test SLMP connection handling"""

    async def test_connect_success(self, slmp_simulator, slmp_plc_info, network_config):
        """Test successful connection to SLMP simulator"""
        async with PLCDataCollector(slmp_plc_info, network_config) as collector:
            assert collector._handler.is_connected is True

    async def test_connect_wrong_port(self, slmp_simulator, network_config):
        """Test connection failure with wrong port"""
        plc_info = PLCInfo(
            ip_address="127.0.0.1",
            protocol=Protocol.SLMP,
            port=59999,  # Wrong port
        )
        async with PLCDataCollector(plc_info, network_config) as collector:
            # Handler returns False on failure, does not raise
            assert not collector._handler.is_connected


class TestSLMPDataRead:
    """Test SLMP data reading"""

    async def test_read_single_address(self, slmp_simulator, slmp_plc_info, network_config):
        """Test reading a single address"""
        async with PLCDataCollector(slmp_plc_info, network_config) as collector:
            data_points = await collector.collect_range(DeviceType.D, 0, 0)

        assert len(data_points) == 1
        assert data_points[0].status == StatusCode.OK
        assert data_points[0].value is not None

    async def test_read_address_range(self, slmp_simulator, slmp_plc_info, network_config):
        """Test reading an address range"""
        async with PLCDataCollector(slmp_plc_info, network_config) as collector:
            data_points = await collector.collect_range(DeviceType.D, 0, 99)

        assert len(data_points) == 100

        # Check all have valid status
        ok_count = sum(1 for dp in data_points if dp.status == StatusCode.OK)
        assert ok_count == 100

    async def test_read_large_range(self, slmp_simulator, slmp_plc_info, network_config):
        """Test reading a large address range (triggers chunking)"""
        async with PLCDataCollector(slmp_plc_info, network_config) as collector:
            data_points = await collector.collect_range(DeviceType.D, 0, 999)

        assert len(data_points) == 1000

    async def test_read_m_device(self, slmp_simulator, slmp_plc_info, network_config):
        """Test reading M (bit) device"""
        async with PLCDataCollector(slmp_plc_info, network_config) as collector:
            data_points = await collector.collect_range(DeviceType.M, 0, 15)

        assert len(data_points) == 16

        # M devices should have 0 or 1 values
        for dp in data_points:
            if dp.status == StatusCode.OK:
                assert dp.value in [0, 1]


class TestSLMPDeniedAddresses:
    """Test SLMP denied address handling with binary search"""

    async def test_denied_address_range(self, slmp_simulator, slmp_plc_info, network_config):
        """Test handling of denied address range (D5000-D5100)"""
        async with PLCDataCollector(slmp_plc_info, network_config) as collector:
            # Read range that includes denied addresses
            data_points = await collector.collect_range(DeviceType.D, 5000, 5100)
            denied = collector.get_denied_addresses()

        # Should have data points for all addresses
        assert len(data_points) == 101

        # All should be marked as illegal address
        illegal_count = sum(1 for dp in data_points if dp.status == StatusCode.NG_ILLEGAL_ADDR)
        assert illegal_count == 101

        # Denied addresses should be recorded
        assert len(denied) > 0

    async def test_binary_search_isolates_denied(self, slmp_simulator, slmp_plc_info, network_config):
        """Test binary search correctly isolates denied addresses"""
        async with PLCDataCollector(slmp_plc_info, network_config) as collector:
            # Read range that spans valid and invalid addresses
            # D4900-D5200 includes denied range D5000-D5100
            data_points = await collector.collect_range(DeviceType.D, 4900, 5200)

        # Should have all data points
        assert len(data_points) == 301

        # Count successful vs denied
        ok_count = sum(1 for dp in data_points if dp.status == StatusCode.OK)
        denied_count = sum(1 for dp in data_points if dp.status == StatusCode.NG_ILLEGAL_ADDR)

        # D4900-D4999 and D5101-D5200 should be OK (200 addresses)
        # D5000-D5100 should be denied (101 addresses)
        assert ok_count == 200
        assert denied_count == 101

    async def test_denied_addresses_cached(self, slmp_simulator, slmp_plc_info, network_config):
        """Test that denied addresses are cached for future reads"""
        async with PLCDataCollector(slmp_plc_info, network_config) as collector:
            # First read - will discover denied addresses
            await collector.collect_range(DeviceType.D, 5000, 5100)
            denied_first = collector.get_denied_addresses().copy()

            # Second read - should skip denied addresses
            await collector.collect_range(DeviceType.D, 5000, 5100)
            denied_second = collector.get_denied_addresses()

        # Denied addresses should be the same
        assert denied_first == denied_second


class TestSLMPFullScan:
    """Test SLMP full scan functionality"""

    async def test_full_scan(self, slmp_simulator, slmp_plc_info, network_config):
        """Test full scan of SLMP device"""
        # Limit range for faster test
        custom_ranges = [
            DeviceRange(DeviceType.D, 0, 100),
            DeviceRange(DeviceType.M, 0, 31),
        ]

        # Modify default ranges temporarily
        from plc_discovery import config

        original_ranges = config.DEFAULT_DEVICE_RANGES.get(Protocol.SLMP)
        config.DEFAULT_DEVICE_RANGES[Protocol.SLMP] = custom_ranges

        try:
            async with PLCDataCollector(slmp_plc_info, network_config) as collector:
                data_points = await collector.collect_full_scan()

            # Should have D0-D100 (101) + M0-M31 (32) = 133 points
            assert len(data_points) >= 133
        finally:
            # Restore original ranges
            config.DEFAULT_DEVICE_RANGES[Protocol.SLMP] = original_ranges


class TestSLMPStatistics:
    """Test statistics tracking"""

    async def test_statistics(self, slmp_simulator, slmp_plc_info, network_config):
        """Test that statistics are correctly tracked"""
        async with PLCDataCollector(slmp_plc_info, network_config) as collector:
            await collector.collect_range(DeviceType.D, 0, 99)
            stats = collector.get_statistics()

        assert stats["total_points"] == 100
        assert stats["success_count"] == 100
        assert stats["illegal_address_count"] == 0
        assert "100" in stats["success_rate"]

    async def test_statistics_with_errors(self, slmp_simulator, slmp_plc_info, network_config):
        """Test statistics include error counts"""
        async with PLCDataCollector(slmp_plc_info, network_config) as collector:
            await collector.collect_range(DeviceType.D, 5000, 5100)
            stats = collector.get_statistics()

        assert stats["total_points"] == 101
        assert stats["illegal_address_count"] == 101
        assert stats["success_count"] == 0


class TestSLMPDataValues:
    """Test that data values are correctly read"""

    async def test_data_values_in_range(self, slmp_simulator, slmp_plc_info, network_config):
        """Test that data values are within expected range"""
        async with PLCDataCollector(slmp_plc_info, network_config) as collector:
            data_points = await collector.collect_range(DeviceType.D, 0, 9)

        for dp in data_points:
            if dp.status == StatusCode.OK:
                # Values should be 16-bit (0-65535)
                assert 0 <= dp.value <= 65535

    async def test_raw_hex_format(self, slmp_simulator, slmp_plc_info, network_config):
        """Test that raw hex values are correctly formatted"""
        async with PLCDataCollector(slmp_plc_info, network_config) as collector:
            data_points = await collector.collect_range(DeviceType.D, 0, 0)

        dp = data_points[0]
        if dp.status == StatusCode.OK:
            # raw_hex is formatted as '0xNNNN' (6 chars with 0x prefix)
            assert dp.raw_hex is not None
            assert dp.raw_hex.startswith("0x")
            # Should be valid hex (strip 0x prefix)
            int(dp.raw_hex, 16)
