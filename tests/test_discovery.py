"""
Tests for discovery module
"""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio

from plc_discovery.config import Protocol, PLCInfo, NetworkConfig
from plc_discovery.discovery import PLCDiscovery, discover_plcs


class TestPLCDiscovery:
    """Tests for PLCDiscovery class"""
    
    def test_discovery_creation(self, network_config):
        """Test PLCDiscovery creation"""
        discovery = PLCDiscovery(network_config)
        assert discovery.config == network_config
        assert discovery.discovered_plcs == {}
    
    def test_discovery_default_config(self):
        """Test PLCDiscovery with default config"""
        discovery = PLCDiscovery()
        assert discovery.config.discovery_timeout_ms == 1000
    
    def test_set_progress_callback(self, network_config):
        """Test setting progress callback"""
        discovery = PLCDiscovery(network_config)
        callback = MagicMock()
        discovery.set_progress_callback(callback)
        
        discovery._report_progress("Test message", 1, 10)
        callback.assert_called_once_with("Test message", 1, 10)
    
    @pytest.mark.asyncio
    @patch('plc_discovery.discovery.is_port_open')
    async def test_probe_host_slmp(self, mock_port_open, network_config):
        """Test probing host with SLMP port open"""
        # Only SLMP port is open
        def port_check(ip, port, timeout):
            return port == 5001
        
        mock_port_open.side_effect = port_check
        
        discovery = PLCDiscovery(network_config)
        
        with patch.object(discovery, '_get_detailed_info', new_callable=AsyncMock) as mock_detail:
            mock_detail.return_value = PLCInfo(
                ip_address="192.168.1.10",
                protocol=Protocol.SLMP,
                port=5001
            )
            
            result = await discovery._probe_host("192.168.1.10", None)
        
        assert result is not None
        assert result.ip_address == "192.168.1.10"
        assert result.protocol == Protocol.SLMP
    
    @pytest.mark.asyncio
    @patch('plc_discovery.discovery.is_port_open')
    async def test_probe_host_no_plc(self, mock_port_open, network_config):
        """Test probing host with no PLC ports open"""
        mock_port_open.return_value = False
        
        discovery = PLCDiscovery(network_config)
        result = await discovery._probe_host("192.168.1.10", None)
        
        assert result is None
    
    @pytest.mark.asyncio
    @patch('plc_discovery.discovery.is_port_open')
    async def test_probe_host_with_mac(self, mock_port_open, network_config):
        """Test probing host with MAC address"""
        mock_port_open.side_effect = lambda ip, port, timeout: port == 5001
        
        discovery = PLCDiscovery(network_config)
        
        with patch.object(discovery, '_get_detailed_info', new_callable=AsyncMock) as mock_detail:
            mock_detail.side_effect = lambda plc: plc
            
            result = await discovery._probe_host(
                "192.168.1.10",
                "00:00:1C:12:34:56"  # Mitsubishi OUI
            )
        
        assert result is not None
        assert result.mac_address == "00:00:1C:12:34:56"
        assert result.manufacturer == "三菱電機"
    
    def test_get_results(self, network_config, sample_plc_info):
        """Test getting discovery results"""
        discovery = PLCDiscovery(network_config)
        discovery.discovered_plcs["192.168.1.10"] = sample_plc_info
        
        results = discovery.get_results()
        
        assert len(results) == 1
        assert results[0].ip_address == "192.168.1.10"
    
    def test_clear(self, network_config, sample_plc_info):
        """Test clearing discovery results"""
        discovery = PLCDiscovery(network_config)
        discovery.discovered_plcs["192.168.1.10"] = sample_plc_info
        
        discovery.clear()
        
        assert len(discovery.discovered_plcs) == 0


class TestDiscoverPLCsConvenience:
    """Tests for discover_plcs convenience function"""
    
    @pytest.mark.asyncio
    @patch.object(PLCDiscovery, 'discover_ip_range', new_callable=AsyncMock)
    async def test_discover_with_ip_range(self, mock_discover, network_config, sample_plc_list):
        """Test discover_plcs with IP range"""
        mock_discover.return_value = sample_plc_list
        
        results = await discover_plcs(
            ip_range="192.168.1.0/24",
            config=network_config
        )
        
        mock_discover.assert_called_once_with("192.168.1.0/24")
        assert len(results) == 3
    
    @pytest.mark.asyncio
    @patch.object(PLCDiscovery, 'discover_same_segment', new_callable=AsyncMock)
    async def test_discover_same_segment(self, mock_discover, network_config, sample_plc_list):
        """Test discover_plcs without IP range"""
        mock_discover.return_value = sample_plc_list
        
        results = await discover_plcs(config=network_config)
        
        mock_discover.assert_called_once()
        assert len(results) == 3


class TestDiscoveryIPRangeScan:
    """Tests for IP range scanning"""
    
    @pytest.mark.asyncio
    async def test_discover_ip_range_empty(self, network_config):
        """Test discovery with invalid IP range"""
        discovery = PLCDiscovery(network_config)
        
        with patch.object(discovery, '_probe_host', new_callable=AsyncMock) as mock_probe:
            mock_probe.return_value = None
            results = await discovery.discover_ip_range("invalid_range")
        
        assert len(results) == 0
    
    @pytest.mark.asyncio
    async def test_discover_ip_range_with_results(self, network_config):
        """Test discovery with valid results"""
        discovery = PLCDiscovery(network_config)
        
        plc_info = PLCInfo(
            ip_address="192.168.1.10",
            protocol=Protocol.SLMP,
            port=5001
        )
        
        with patch.object(discovery, '_probe_host', new_callable=AsyncMock) as mock_probe:
            # Only one IP responds
            async def probe_side_effect(ip, mac):
                if ip == "192.168.1.10":
                    return plc_info
                return None
            
            mock_probe.side_effect = probe_side_effect
            results = await discovery.discover_ip_range("192.168.1.10-11")
        
        assert len(results) == 1
        assert results[0].ip_address == "192.168.1.10"


class TestProtocolQueries:
    """Tests for protocol-specific query methods"""
    
    @pytest.mark.asyncio
    async def test_query_slmp_info(self, network_config):
        """Test SLMP info query"""
        discovery = PLCDiscovery(network_config)
        plc_info = PLCInfo(
            ip_address="192.168.1.10",
            protocol=Protocol.SLMP,
            port=5001
        )
        
        # The query method should return the plc_info even if library not available
        result = await discovery._query_slmp_info(plc_info)
        
        assert result.ip_address == "192.168.1.10"
    
    @pytest.mark.asyncio
    async def test_query_modbus_info(self, network_config):
        """Test Modbus info query"""
        discovery = PLCDiscovery(network_config)
        plc_info = PLCInfo(
            ip_address="192.168.1.10",
            protocol=Protocol.MODBUS_TCP,
            port=502
        )
        
        # The query method should return the plc_info even if library not available
        result = await discovery._query_modbus_info(plc_info)
        
        assert result.ip_address == "192.168.1.10"

