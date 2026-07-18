"""
S7 Integration Tests

Tests actual communication with Siemens S7 simulator.

Note: snap7 library always connects to port 102 (ISO-on-TCP standard).
Custom port configuration is not supported by snap7, so these tests
require the simulator to run on port 102 (requires elevated privileges
on some systems). Tests are skipped in CI environments.
"""

import asyncio
import pytest

from plc_discovery.config import (
    Protocol, DeviceType, ScanMode, PLCInfo, DataPoint,
    NetworkConfig, DeviceRange, StatusCode
)
from plc_discovery.collector import PLCDataCollector

pytestmark = [
    pytest.mark.integration,
    pytest.mark.asyncio,
    pytest.mark.skip(reason="snap7 only supports port 102; S7 simulator cannot bind to privileged port in test environment"),
]

class TestS7Connection:
    """Test S7 connection handling"""
    
    async def test_connect_success(self, s7_simulator, s7_plc_info, network_config):
        """Test successful connection"""
        async with PLCDataCollector(s7_plc_info, network_config) as collector:
            assert collector._handler.is_connected is True

class TestS7DataRead:
    """Test S7 data reading"""
    
    async def test_read_data_block(self, s7_simulator, s7_plc_info, network_config):
        """Test reading data blocks"""
        async with PLCDataCollector(s7_plc_info, network_config) as collector:
            data_points = await collector.collect_range(DeviceType.DB, 0, 99)
        assert len(data_points) == 100
        ok_count = sum(1 for dp in data_points if dp.status == StatusCode.OK)
        assert ok_count == 100

class TestS7DeniedAddresses:
    """Test S7 denied address handling"""
    
    async def test_denied_address_range(self, s7_simulator, s7_plc_info, network_config):
        """Test handling of denied address range (500-550)"""
        async with PLCDataCollector(s7_plc_info, network_config) as collector:
            data_points = await collector.collect_range(DeviceType.DB, 500, 550)
        assert len(data_points) == 51
        illegal_count = sum(1 for dp in data_points if dp.status == StatusCode.NG_ILLEGAL_ADDR)
        assert illegal_count == 51

    async def test_binary_search_mixed_range(self, s7_simulator, s7_plc_info, network_config):
        """Test binary search with mixed valid/invalid addresses"""
        async with PLCDataCollector(s7_plc_info, network_config) as collector:
            data_points = await collector.collect_range(DeviceType.DB, 480, 570)
        
        assert len(data_points) == 91
        ok_count = sum(1 for dp in data_points if dp.status == StatusCode.OK)
        denied_count = sum(1 for dp in data_points if dp.status == StatusCode.NG_ILLEGAL_ADDR)
        
        assert ok_count == 40  # 480-499 (20) and 551-570 (20)
        assert denied_count == 51 # 500-550 (51)
