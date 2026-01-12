"""
Tests for data_types module
"""

import struct
import pytest

from plc_discovery.data_types import (
    DataType, ByteOrder, TypedValue, DataTypeConverter,
    DataTypeMapping, DataTypeManager
)


class TestDataTypeConverter:
    """Tests for DataTypeConverter class"""
    
    def test_word_conversion(self):
        """Test WORD (16-bit unsigned) conversion"""
        result = DataTypeConverter.convert([0x1234], DataType.WORD)
        assert result == 0x1234
        
        result = DataTypeConverter.convert([0xFFFF], DataType.WORD)
        assert result == 0xFFFF
    
    def test_int16_conversion(self):
        """Test INT16 (16-bit signed) conversion"""
        # Positive value
        result = DataTypeConverter.convert([0x1234], DataType.INT16)
        assert result == 0x1234
        
        # Negative value (-1)
        result = DataTypeConverter.convert([0xFFFF], DataType.INT16)
        assert result == -1
        
        # Minimum value (-32768)
        result = DataTypeConverter.convert([0x8000], DataType.INT16)
        assert result == -32768
    
    def test_dword_conversion_little_endian(self):
        """Test DWORD (32-bit unsigned) conversion - little endian"""
        # 0x12345678 stored as low word first
        words = [0x5678, 0x1234]
        result = DataTypeConverter.convert(words, DataType.DWORD, ByteOrder.LITTLE_ENDIAN)
        assert result == 0x12345678
    
    def test_dword_conversion_big_endian(self):
        """Test DWORD (32-bit unsigned) conversion - big endian"""
        words = [0x1234, 0x5678]
        result = DataTypeConverter.convert(words, DataType.DWORD, ByteOrder.BIG_ENDIAN)
        assert result == 0x12345678
    
    def test_int32_conversion(self):
        """Test INT32 (32-bit signed) conversion"""
        # Negative value
        words = [0xFFFF, 0xFFFF]
        result = DataTypeConverter.convert(words, DataType.INT32, ByteOrder.LITTLE_ENDIAN)
        assert result == -1
        
        # Positive value
        words = [0x0001, 0x0000]
        result = DataTypeConverter.convert(words, DataType.INT32, ByteOrder.LITTLE_ENDIAN)
        assert result == 1
    
    def test_float_conversion(self):
        """Test FLOAT (32-bit IEEE 754) conversion"""
        # Pack a known float value
        test_value = 3.14159
        packed = struct.pack('<f', test_value)
        low = struct.unpack('<H', packed[0:2])[0]
        high = struct.unpack('<H', packed[2:4])[0]
        
        words = [low, high]
        result = DataTypeConverter.convert(words, DataType.FLOAT, ByteOrder.LITTLE_ENDIAN)
        
        assert abs(result - test_value) < 0.0001
    
    def test_float_common_values(self):
        """Test FLOAT conversion with common values"""
        # Test 0.0
        words = [0x0000, 0x0000]
        result = DataTypeConverter.convert(words, DataType.FLOAT, ByteOrder.LITTLE_ENDIAN)
        assert result == 0.0
        
        # Test 1.0 (0x3F800000)
        words = [0x0000, 0x3F80]
        result = DataTypeConverter.convert(words, DataType.FLOAT, ByteOrder.LITTLE_ENDIAN)
        assert result == 1.0
        
        # Test -1.0 (0xBF800000)
        words = [0x0000, 0xBF80]
        result = DataTypeConverter.convert(words, DataType.FLOAT, ByteOrder.LITTLE_ENDIAN)
        assert result == -1.0
    
    def test_double_conversion(self):
        """Test DOUBLE (64-bit IEEE 754) conversion"""
        test_value = 3.141592653589793
        packed = struct.pack('<d', test_value)
        words = [
            struct.unpack('<H', packed[0:2])[0],
            struct.unpack('<H', packed[2:4])[0],
            struct.unpack('<H', packed[4:6])[0],
            struct.unpack('<H', packed[6:8])[0],
        ]
        
        result = DataTypeConverter.convert(words, DataType.DOUBLE, ByteOrder.LITTLE_ENDIAN)
        
        assert abs(result - test_value) < 1e-10
    
    def test_bcd16_conversion(self):
        """Test BCD16 (16-bit BCD) conversion"""
        # BCD 1234 = 0x1234
        result = DataTypeConverter.convert([0x1234], DataType.BCD16)
        assert result == 1234
        
        # BCD 9999
        result = DataTypeConverter.convert([0x9999], DataType.BCD16)
        assert result == 9999
        
        # BCD 0
        result = DataTypeConverter.convert([0x0000], DataType.BCD16)
        assert result == 0
    
    def test_bcd16_invalid(self):
        """Test BCD16 with invalid digits"""
        # Invalid BCD (digit A)
        result = DataTypeConverter.convert([0x123A], DataType.BCD16)
        assert result is None
    
    def test_bcd32_conversion(self):
        """Test BCD32 (32-bit BCD) conversion"""
        # BCD 12345678 stored as two words
        words = [0x5678, 0x1234]
        result = DataTypeConverter.convert(words, DataType.BCD32, ByteOrder.LITTLE_ENDIAN)
        assert result == 12345678
    
    def test_string_conversion(self):
        """Test STRING conversion"""
        # "HELLO" = H(48), E(45), L(4C), L(4C), O(4F)
        # Stored as: 0x4548 (EH), 0x4C4C (LL), 0x004F (O\0)
        words = [0x4548, 0x4C4C, 0x004F]
        result = DataTypeConverter.convert(words, DataType.STRING)
        assert result == "HELLO"
    
    def test_string_with_null_terminator(self):
        """Test STRING stops at null terminator"""
        # "HI" followed by garbage
        words = [0x4948, 0x0000, 0xFFFF]  # "HI" + null + garbage
        result = DataTypeConverter.convert(words, DataType.STRING)
        assert result == "HI"
    
    def test_bit_conversion(self):
        """Test BIT/BOOL conversion"""
        result = DataTypeConverter.convert([0x0001], DataType.BIT)
        assert result is True
        
        result = DataTypeConverter.convert([0x0000], DataType.BIT)
        assert result is False
        
        result = DataTypeConverter.convert([0xFFFE], DataType.BIT)
        assert result is False  # Only LSB matters
    
    def test_raw_conversion(self):
        """Test RAW (hex string) conversion"""
        words = [0x1234, 0x5678]
        result = DataTypeConverter.convert(words, DataType.RAW, ByteOrder.LITTLE_ENDIAN)
        assert result == "34127856"
    
    def test_qword_conversion(self):
        """Test QWORD (64-bit unsigned) conversion"""
        words = [0x0001, 0x0000, 0x0000, 0x0000]
        result = DataTypeConverter.convert(words, DataType.QWORD, ByteOrder.LITTLE_ENDIAN)
        assert result == 1
        
        # Large value
        words = [0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF]
        result = DataTypeConverter.convert(words, DataType.QWORD, ByteOrder.LITTLE_ENDIAN)
        assert result == 0xFFFFFFFFFFFFFFFF
    
    def test_word_swap_byte_order(self):
        """Test word-swapped byte orders"""
        # 0x12345678 with word swap
        words = [0x1234, 0x5678]  # Swapped words
        result = DataTypeConverter.convert(
            words, DataType.DWORD, ByteOrder.LITTLE_ENDIAN_WORD_SWAP
        )
        assert result == 0x12345678
    
    def test_empty_words(self):
        """Test conversion with empty word list"""
        result = DataTypeConverter.convert([], DataType.WORD)
        assert result is None
    
    def test_get_word_count(self):
        """Test word count for data types"""
        assert DataTypeConverter.get_word_count(DataType.WORD) == 1
        assert DataTypeConverter.get_word_count(DataType.DWORD) == 2
        assert DataTypeConverter.get_word_count(DataType.FLOAT) == 2
        assert DataTypeConverter.get_word_count(DataType.DOUBLE) == 4
        assert DataTypeConverter.get_word_count(DataType.QWORD) == 4
        assert DataTypeConverter.get_word_count(DataType.INT16) == 1
    
    def test_convert_batch(self):
        """Test batch conversion of multiple values"""
        # 4 WORD values
        words = [100, 200, 300, 400]
        results = DataTypeConverter.convert_batch(words, DataType.WORD)
        assert results == [100, 200, 300, 400]
        
        # 2 DWORD values
        words = [0x1234, 0x5678, 0xABCD, 0xEF01]
        results = DataTypeConverter.convert_batch(
            words, DataType.DWORD, ByteOrder.LITTLE_ENDIAN
        )
        assert len(results) == 2


class TestToString:
    """Tests for to_string conversion"""
    
    def test_float_string(self):
        """Test float to string"""
        result = DataTypeConverter.to_string(3.14159, DataType.FLOAT)
        assert "3.14159" in result
    
    def test_bool_string(self):
        """Test bool to string"""
        assert DataTypeConverter.to_string(True, DataType.BIT) == "ON"
        assert DataTypeConverter.to_string(False, DataType.BIT) == "OFF"
    
    def test_none_string(self):
        """Test None value"""
        assert DataTypeConverter.to_string(None, DataType.WORD) == ""


class TestTypedValue:
    """Tests for TypedValue dataclass"""
    
    def test_auto_conversion(self):
        """Test automatic conversion on creation"""
        typed = TypedValue(
            raw_words=[0x1234],
            data_type=DataType.WORD,
            byte_order=ByteOrder.LITTLE_ENDIAN
        )
        
        assert typed.converted_value == 0x1234
        assert typed.display_string == "4660"
    
    def test_float_typed_value(self):
        """Test TypedValue with float"""
        # 1.0 in IEEE 754
        typed = TypedValue(
            raw_words=[0x0000, 0x3F80],
            data_type=DataType.FLOAT,
            byte_order=ByteOrder.LITTLE_ENDIAN
        )
        
        assert typed.converted_value == 1.0


class TestDataTypeMapping:
    """Tests for DataTypeMapping class"""
    
    def test_contains(self):
        """Test address containment check"""
        mapping = DataTypeMapping(
            start_address=100,
            end_address=199,
            data_type=DataType.FLOAT
        )
        
        assert mapping.contains(100)
        assert mapping.contains(150)
        assert mapping.contains(199)
        assert not mapping.contains(99)
        assert not mapping.contains(200)


class TestDataTypeManager:
    """Tests for DataTypeManager class"""
    
    def test_add_mapping(self):
        """Test adding mappings"""
        manager = DataTypeManager()
        manager.add_mapping(DataTypeMapping(0, 99, DataType.WORD))
        manager.add_mapping(DataTypeMapping(100, 199, DataType.FLOAT))
        
        assert len(manager.mappings) == 2
    
    def test_get_type_for_address(self):
        """Test getting type for address"""
        manager = DataTypeManager()
        manager.add_mapping(DataTypeMapping(0, 99, DataType.WORD))
        manager.add_mapping(DataTypeMapping(100, 199, DataType.FLOAT))
        
        dt, bo = manager.get_type_for_address(50)
        assert dt == DataType.WORD
        
        dt, bo = manager.get_type_for_address(150)
        assert dt == DataType.FLOAT
    
    def test_default_type(self):
        """Test default type for unmapped addresses"""
        manager = DataTypeManager()
        manager.add_mapping(DataTypeMapping(0, 99, DataType.FLOAT))
        
        dt, bo = manager.get_type_for_address(1000)  # Unmapped
        assert dt == DataType.WORD  # Default
    
    def test_set_default(self):
        """Test setting custom default"""
        manager = DataTypeManager()
        manager.set_default(DataType.INT16, ByteOrder.BIG_ENDIAN)
        
        dt, bo = manager.get_type_for_address(1000)
        assert dt == DataType.INT16
        assert bo == ByteOrder.BIG_ENDIAN
    
    def test_from_config(self):
        """Test creating from configuration"""
        config = {
            "default_type": "DWORD",
            "default_byte_order": "big",
            "mappings": [
                {"start": 0, "end": 99, "type": "FLOAT", "description": "Temperatures"},
                {"start": 100, "end": 199, "type": "INT32", "byte_order": "little"},
            ]
        }
        
        manager = DataTypeManager.from_config(config)
        
        assert manager.default_type == DataType.DWORD
        assert len(manager.mappings) == 2
        
        dt, _ = manager.get_type_for_address(50)
        assert dt == DataType.FLOAT
    
    def test_clear(self):
        """Test clearing mappings"""
        manager = DataTypeManager()
        manager.add_mapping(DataTypeMapping(0, 99, DataType.WORD))
        manager.clear()
        
        assert len(manager.mappings) == 0


