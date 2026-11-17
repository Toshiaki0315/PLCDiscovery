"""
Tests for config module
"""

from plc_discovery.config import (
    Protocol,
    DeviceType,
    StatusCode,
    NetworkConfig,
    DeviceRange,
    PLCInfo,
    DataPoint,
    PROTOCOL_PORTS,
    MAX_READ_WORDS,
    SAFE_READ_WORDS,
    MANUFACTURER_OUI,
    DEFAULT_DEVICE_RANGES,
)


class TestProtocolEnum:
    """Tests for Protocol enum"""

    def test_protocol_values(self):
        """Test all protocol values exist"""
        assert Protocol.SLMP
        assert Protocol.ETHERNET_IP
        assert Protocol.MODBUS_TCP
        assert Protocol.S7
        assert Protocol.FINS

    def test_protocol_ports_mapping(self):
        """Test protocol to port mapping"""
        assert PROTOCOL_PORTS[Protocol.SLMP] == 5001
        assert PROTOCOL_PORTS[Protocol.ETHERNET_IP] == 44818
        assert PROTOCOL_PORTS[Protocol.MODBUS_TCP] == 502
        assert PROTOCOL_PORTS[Protocol.S7] == 102


class TestDeviceTypeEnum:
    """Tests for DeviceType enum"""

    def test_device_types_exist(self):
        """Test all device types exist"""
        assert DeviceType.D.value == "D"
        assert DeviceType.M.value == "M"
        assert DeviceType.W.value == "W"
        assert DeviceType.R.value == "R"
        assert DeviceType.DM.value == "DM"
        assert DeviceType.HR.value == "HR"
        assert DeviceType.IR.value == "IR"
        assert DeviceType.DB.value == "DB"


class TestStatusCodeEnum:
    """Tests for StatusCode enum"""

    def test_status_codes(self):
        """Test all status codes exist"""
        assert StatusCode.OK.value == "OK"
        assert StatusCode.NG_ILLEGAL_ADDR.value == "NG_ILLEGAL_ADDR"
        assert StatusCode.NG_TIMEOUT.value == "NG_TIMEOUT"
        assert StatusCode.NG_COMM_ERROR.value == "NG_COMM_ERROR"
        assert StatusCode.NG_UNSUPPORTED.value == "NG_UNSUPPORTED"


class TestNetworkConfig:
    """Tests for NetworkConfig dataclass"""

    def test_default_values(self):
        """Test default configuration values"""
        config = NetworkConfig()
        assert config.discovery_timeout_ms == 1000
        assert config.discovery_retry_count == 3
        assert config.packet_interval_ms == 50
        assert config.retry_interval_ms == 200
        assert config.request_timeout_ms == 5000
        assert config.max_concurrent == 1

    def test_custom_values(self):
        """Test custom configuration values"""
        config = NetworkConfig(
            discovery_timeout_ms=500,
            packet_interval_ms=100,
            max_concurrent=5
        )
        assert config.discovery_timeout_ms == 500
        assert config.packet_interval_ms == 100
        assert config.max_concurrent == 5


class TestDeviceRange:
    """Tests for DeviceRange dataclass"""

    def test_device_range_creation(self):
        """Test DeviceRange creation"""
        dr = DeviceRange(DeviceType.D, 0, 999)
        assert dr.device_type == DeviceType.D
        assert dr.start_address == 0
        assert dr.end_address == 999

    def test_device_range_count(self):
        """Test DeviceRange count property"""
        dr = DeviceRange(DeviceType.D, 0, 99)
        assert dr.count == 100

        dr2 = DeviceRange(DeviceType.M, 100, 100)
        assert dr2.count == 1


class TestPLCInfo:
    """Tests for PLCInfo dataclass"""

    def test_plc_info_creation(self):
        """Test PLCInfo creation"""
        plc = PLCInfo(ip_address="192.168.1.10")
        assert plc.ip_address == "192.168.1.10"
        assert plc.mac_address is None
        assert plc.manufacturer is None

    def test_plc_info_full(self):
        """Test PLCInfo with all fields"""
        plc = PLCInfo(
            ip_address="192.168.1.10",
            mac_address="00:26:92:12:34:56",
            manufacturer="三菱電機",
            model="iQ-R",
            protocol=Protocol.SLMP,
            port=5001
        )
        assert plc.manufacturer == "三菱電機"
        assert plc.protocol == Protocol.SLMP

    def test_plc_info_to_dict(self):
        """Test PLCInfo to_dict method"""
        plc = PLCInfo(
            ip_address="192.168.1.10",
            protocol=Protocol.SLMP,
            port=5001
        )
        d = plc.to_dict()

        assert d["ip_address"] == "192.168.1.10"
        assert d["protocol"] == "SLMP"
        assert d["port"] == 5001
        assert d["mac_address"] == ""


class TestDataPoint:
    """Tests for DataPoint dataclass"""

    def test_data_point_creation(self):
        """Test DataPoint creation"""
        dp = DataPoint(
            address="D100",
            value=1234,
            raw_hex="0x04D2",
            status=StatusCode.OK,
            timestamp="2024-01-01 10:00:00"
        )
        assert dp.address == "D100"
        assert dp.value == 1234
        assert dp.raw_hex == "0x04D2"
        assert dp.status == StatusCode.OK

    def test_data_point_error(self):
        """Test DataPoint with error status"""
        dp = DataPoint(
            address="D999",
            status=StatusCode.NG_ILLEGAL_ADDR,
            timestamp="2024-01-01 10:00:00"
        )
        assert dp.value is None
        assert dp.raw_hex is None
        assert dp.status == StatusCode.NG_ILLEGAL_ADDR

    def test_data_point_to_dict(self):
        """Test DataPoint to_dict method"""
        dp = DataPoint(
            address="D100",
            value=1234,
            raw_hex="0x04D2",
            status=StatusCode.OK,
            timestamp="2024-01-01 10:00:00"
        )
        d = dp.to_dict()

        assert d["address"] == "D100"
        assert d["value"] == 1234
        assert d["status"] == "OK"


class TestConstants:
    """Tests for module constants"""

    def test_max_read_words(self):
        """Test MAX_READ_WORDS values"""
        assert MAX_READ_WORDS[Protocol.SLMP] == 960
        assert MAX_READ_WORDS[Protocol.MODBUS_TCP] == 125
        assert MAX_READ_WORDS[Protocol.ETHERNET_IP] == 252

    def test_safe_read_words(self):
        """Test SAFE_READ_WORDS values are less than MAX"""
        for protocol in Protocol:
            if protocol in MAX_READ_WORDS and protocol in SAFE_READ_WORDS:
                assert SAFE_READ_WORDS[protocol] < MAX_READ_WORDS[protocol]

    def test_manufacturer_oui(self):
        """Test manufacturer OUI mapping"""
        assert "00:26:92" in MANUFACTURER_OUI
        assert MANUFACTURER_OUI["00:26:92"] == "三菱電機"
        assert "00:00:0A" in MANUFACTURER_OUI
        assert MANUFACTURER_OUI["00:00:0A"] == "オムロン"

    def test_default_device_ranges(self):
        """Test default device ranges exist for protocols"""
        assert Protocol.SLMP in DEFAULT_DEVICE_RANGES
        assert Protocol.MODBUS_TCP in DEFAULT_DEVICE_RANGES

        # Check SLMP has D device range
        slmp_ranges = DEFAULT_DEVICE_RANGES[Protocol.SLMP]
        device_types = [r.device_type for r in slmp_ranges]
        assert DeviceType.D in device_types
