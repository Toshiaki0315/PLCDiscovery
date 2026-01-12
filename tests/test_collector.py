"""
Tests for collector module
"""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio

from plc_discovery.config import (
    Protocol, DeviceType, DeviceRange, PLCInfo, DataPoint,
    StatusCode, NetworkConfig, ScanMode
)
from plc_discovery.collector import (
    PLCDataCollector, collect_plc_data, get_handler_for_protocol,
    PROTOCOL_HANDLERS
)
from plc_discovery.protocols.base import BaseProtocolHandler


class TestPLCDataCollector:
    """Tests for PLCDataCollector class"""
    
    def test_collector_creation(self, sample_plc_info, network_config):
        """Test collector creation"""
        collector = PLCDataCollector(sample_plc_info, network_config)
        assert collector.plc_info == sample_plc_info
        assert collector.config == network_config
    
    def test_collector_default_config(self, sample_plc_info):
        """Test collector with default config"""
        collector = PLCDataCollector(sample_plc_info)
        assert collector.config.packet_interval_ms == 50
    
    def test_set_progress_callback(self, sample_plc_info, network_config):
        """Test setting progress callback"""
        collector = PLCDataCollector(sample_plc_info, network_config)
        callback = MagicMock()
        collector.set_progress_callback(callback)
        
        collector._report_progress("Test message", 1, 10)
        callback.assert_called_once_with("Test message", 1, 10)
    
    @pytest.mark.asyncio
    async def test_connect_success(self, sample_plc_info, network_config):
        """Test successful connection"""
        collector = PLCDataCollector(sample_plc_info, network_config)
        
        # Create mock handler directly
        mock_handler = AsyncMock()
        mock_handler.connect = AsyncMock(return_value=True)
        mock_handler.is_connected = True
        
        # Directly set the handler
        with patch.dict('plc_discovery.collector.PROTOCOL_HANDLERS', {Protocol.SLMP: MagicMock(return_value=mock_handler)}):
            result = await collector.connect()
        
        assert result is True
        mock_handler.connect.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_connect_failure(self, sample_plc_info, network_config):
        """Test connection failure"""
        collector = PLCDataCollector(sample_plc_info, network_config)
        
        with patch('plc_discovery.collector.SLMPHandler') as mock_handler_class:
            mock_handler = AsyncMock()
            mock_handler.connect = AsyncMock(return_value=False)
            mock_handler_class.return_value = mock_handler
            
            result = await collector.connect()
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_connect_no_protocol(self, network_config):
        """Test connection with no protocol specified"""
        plc_info = PLCInfo(ip_address="192.168.1.10")  # No protocol
        collector = PLCDataCollector(plc_info, network_config)
        
        result = await collector.connect()
        assert result is False
    
    @pytest.mark.asyncio
    async def test_disconnect(self, sample_plc_info, network_config):
        """Test disconnection"""
        collector = PLCDataCollector(sample_plc_info, network_config)
        
        # Setup mock handler
        mock_handler = AsyncMock()
        mock_handler.disconnect = AsyncMock()
        mock_handler.get_denied_addresses = MagicMock(return_value={"D100"})
        collector._handler = mock_handler
        
        await collector.disconnect()
        
        mock_handler.disconnect.assert_called_once()
        assert collector._denied_addresses == {"D100"}
    
    @pytest.mark.asyncio
    async def test_collect_range(self, sample_plc_info, network_config, sample_data_points):
        """Test collecting data range"""
        collector = PLCDataCollector(sample_plc_info, network_config)
        
        # Setup mock handler
        mock_handler = AsyncMock()
        mock_handler.is_connected = True
        mock_handler.read_device_range = AsyncMock(return_value=sample_data_points)
        collector._handler = mock_handler
        
        result = await collector.collect_range(DeviceType.D, 0, 3)
        
        assert len(result) == 4
        assert result[0].address == "D0"
        mock_handler.read_device_range.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_collect_range_not_connected(self, sample_plc_info, network_config):
        """Test collecting range when not connected"""
        collector = PLCDataCollector(sample_plc_info, network_config)
        
        result = await collector.collect_range(DeviceType.D, 0, 99)
        
        assert result == []
    
    def test_get_statistics(self, sample_plc_info, network_config, sample_data_points):
        """Test getting collection statistics"""
        collector = PLCDataCollector(sample_plc_info, network_config)
        collector._collected_data = sample_data_points
        
        # Mock handler for denied addresses
        mock_handler = MagicMock()
        mock_handler.get_denied_addresses = MagicMock(return_value={"D2", "D3"})
        collector._handler = mock_handler
        
        stats = collector.get_statistics()
        
        assert stats["total_points"] == 4
        assert stats["success_count"] == 2
        assert stats["illegal_address_count"] == 1
        assert stats["timeout_count"] == 1
        assert stats["denied_addresses"] == 2
    
    def test_clear_data(self, sample_plc_info, network_config, sample_data_points):
        """Test clearing collected data"""
        collector = PLCDataCollector(sample_plc_info, network_config)
        collector._collected_data = sample_data_points
        
        collector.clear_data()
        
        assert collector._collected_data == []
    
    @pytest.mark.asyncio
    async def test_context_manager(self, sample_plc_info, network_config):
        """Test async context manager"""
        mock_handler = AsyncMock()
        mock_handler.connect = AsyncMock(return_value=True)
        mock_handler.disconnect = AsyncMock()
        mock_handler.get_denied_addresses = MagicMock(return_value=set())
        mock_handler.is_connected = True
        
        with patch.dict('plc_discovery.collector.PROTOCOL_HANDLERS', {Protocol.SLMP: MagicMock(return_value=mock_handler)}):
            async with PLCDataCollector(sample_plc_info, network_config) as collector:
                assert collector._handler is not None
            
            mock_handler.disconnect.assert_called_once()


class TestCollectPLCDataConvenience:
    """Tests for collect_plc_data convenience function"""
    
    @pytest.mark.asyncio
    async def test_collect_full_mode(self, sample_plc_info, network_config, sample_data_points):
        """Test full scan mode"""
        with patch('plc_discovery.collector.PLCDataCollector') as mock_collector_class:
            mock_collector = AsyncMock()
            mock_collector.__aenter__ = AsyncMock(return_value=mock_collector)
            mock_collector.__aexit__ = AsyncMock(return_value=False)
            mock_collector.collect_full_scan = AsyncMock(return_value=sample_data_points)
            mock_collector_class.return_value = mock_collector
            
            result = await collect_plc_data(
                sample_plc_info,
                mode=ScanMode.FULL,
                config=network_config
            )
        
        assert len(result) == 4
        mock_collector.collect_full_scan.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_collect_range_mode(self, sample_plc_info, network_config, sample_data_points):
        """Test range scan mode"""
        with patch('plc_discovery.collector.PLCDataCollector') as mock_collector_class:
            mock_collector = AsyncMock()
            mock_collector.__aenter__ = AsyncMock(return_value=mock_collector)
            mock_collector.__aexit__ = AsyncMock(return_value=False)
            mock_collector.collect_range = AsyncMock(return_value=sample_data_points)
            mock_collector_class.return_value = mock_collector
            
            result = await collect_plc_data(
                sample_plc_info,
                mode=ScanMode.RANGE,
                device_type=DeviceType.D,
                start_address=0,
                end_address=99,
                config=network_config
            )
        
        assert len(result) == 4
        mock_collector.collect_range.assert_called_once()


class TestProtocolHandlerMapping:
    """Tests for protocol handler mapping"""
    
    def test_get_handler_for_protocol_slmp(self):
        """Test getting SLMP handler"""
        from plc_discovery.protocols.slmp import SLMPHandler
        handler_class = get_handler_for_protocol(Protocol.SLMP)
        assert handler_class == SLMPHandler
    
    def test_get_handler_for_protocol_modbus(self):
        """Test getting Modbus handler"""
        from plc_discovery.protocols.modbus import ModbusHandler
        handler_class = get_handler_for_protocol(Protocol.MODBUS_TCP)
        assert handler_class == ModbusHandler
    
    def test_get_handler_for_protocol_eip(self):
        """Test getting EtherNet/IP handler"""
        from plc_discovery.protocols.ethernet_ip import EtherNetIPHandler
        handler_class = get_handler_for_protocol(Protocol.ETHERNET_IP)
        assert handler_class == EtherNetIPHandler
    
    def test_get_handler_for_protocol_s7(self):
        """Test getting S7 handler"""
        from plc_discovery.protocols.s7 import S7Handler
        handler_class = get_handler_for_protocol(Protocol.S7)
        assert handler_class == S7Handler
    
    def test_all_protocols_have_handlers(self):
        """Test that all main protocols have handlers"""
        main_protocols = [
            Protocol.SLMP,
            Protocol.ETHERNET_IP,
            Protocol.MODBUS_TCP,
            Protocol.S7
        ]
        
        for protocol in main_protocols:
            assert protocol in PROTOCOL_HANDLERS
            assert PROTOCOL_HANDLERS[protocol] is not None

