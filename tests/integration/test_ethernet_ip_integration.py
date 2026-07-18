"""
EtherNet/IP Integration Tests

Tests actual communication with EtherNet/IP simulator.
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
]

class TestEtherNetIPConnection:
    """Test EtherNet/IP connection handling"""
    
    async def test_connect_success(self, ethernet_ip_simulator, ethernet_ip_plc_info, network_config):
        """Test successful connection"""
        async with PLCDataCollector(ethernet_ip_plc_info, network_config) as collector:
            assert collector._handler.is_connected is True
    
    async def test_connect_wrong_port(self, ethernet_ip_simulator, network_config):
        """Test connection failure with wrong port"""
        plc_info = PLCInfo(
            ip_address="127.0.0.1",
            protocol=Protocol.ETHERNET_IP,
            port=59998,
        )
        async with PLCDataCollector(plc_info, network_config) as collector:
            # Handler returns False on failure, does not raise
            assert not collector._handler.is_connected

@pytest.mark.xfail(reason="pycomm3 CIPDriver generic read is incompatible with our simplified EtherNet/IP simulator")
class TestEtherNetIPDataRead:
    """Test EtherNet/IP data reading"""
    
    async def test_read_data(self, ethernet_ip_simulator, ethernet_ip_plc_info, network_config):
        """Test reading holding registers/integer file"""
        async with PLCDataCollector(ethernet_ip_plc_info, network_config) as collector:
            data_points = await collector.collect_range(DeviceType.HR, 0, 99)
        assert len(data_points) == 100
        ok_count = sum(1 for dp in data_points if dp.status == StatusCode.OK)
        assert ok_count == 100

@pytest.mark.xfail(reason="pycomm3 CIPDriver generic read is incompatible with our simplified EtherNet/IP simulator")
class TestEtherNetIPDeniedAddresses:
    """Test EtherNet/IP denied address handling"""
    
    async def test_denied_address_range(self, ethernet_ip_simulator, ethernet_ip_plc_info, network_config):
        """Test handling of denied address range (100-150)"""
        async with PLCDataCollector(ethernet_ip_plc_info, network_config) as collector:
            data_points = await collector.collect_range(DeviceType.HR, 100, 150)
        assert len(data_points) == 51
        illegal_count = sum(1 for dp in data_points if dp.status == StatusCode.NG_ILLEGAL_ADDR)
        assert illegal_count == 51

    async def test_binary_search_mixed_range(self, ethernet_ip_simulator, ethernet_ip_plc_info, network_config):
        """Test binary search with mixed valid/invalid addresses"""
        async with PLCDataCollector(ethernet_ip_plc_info, network_config) as collector:
            data_points = await collector.collect_range(DeviceType.HR, 80, 170)
        
        assert len(data_points) == 91
        ok_count = sum(1 for dp in data_points if dp.status == StatusCode.OK)
        denied_count = sum(1 for dp in data_points if dp.status == StatusCode.NG_ILLEGAL_ADDR)
        
        assert ok_count == 40  # 80-99 (20) and 151-170 (20)
        assert denied_count == 51 # 100-150 (51)
