"""
Data Type Conversion Module

Provides conversion between raw PLC data and various data types.
Supports WORD, DWORD, FLOAT, DOUBLE, STRING, BCD, and signed variants.
"""

import struct
from enum import Enum
from typing import Any, List, Optional, Tuple, Union
from dataclasses import dataclass


class DataType(Enum):
    """Supported data types for PLC values"""
    # Unsigned integers
    WORD = "WORD"           # 16-bit unsigned integer (1 word)
    DWORD = "DWORD"         # 32-bit unsigned integer (2 words)
    QWORD = "QWORD"         # 64-bit unsigned integer (4 words)
    
    # Signed integers
    INT16 = "INT16"         # 16-bit signed integer (1 word)
    INT32 = "INT32"         # 32-bit signed integer (2 words)
    INT64 = "INT64"         # 64-bit signed integer (4 words)
    
    # Floating point
    FLOAT = "FLOAT"         # 32-bit IEEE 754 float (2 words)
    DOUBLE = "DOUBLE"       # 64-bit IEEE 754 double (4 words)
    
    # Special formats
    BCD16 = "BCD16"         # 16-bit BCD (4 digits)
    BCD32 = "BCD32"         # 32-bit BCD (8 digits)
    
    # String/raw
    STRING = "STRING"       # ASCII string (variable length)
    RAW = "RAW"             # Raw bytes (no conversion)
    
    # Boolean (bit)
    BIT = "BIT"             # Single bit value
    BOOL = "BOOL"           # Boolean (same as BIT)


class ByteOrder(Enum):
    """Byte order for multi-byte values"""
    LITTLE_ENDIAN = "little"    # Intel byte order (most PLCs)
    BIG_ENDIAN = "big"          # Motorola byte order
    
    # Word swap variants (common in PLCs)
    LITTLE_ENDIAN_WORD_SWAP = "little_swap"  # Swap word order
    BIG_ENDIAN_WORD_SWAP = "big_swap"        # Swap word order


@dataclass
class TypedValue:
    """Value with type information"""
    raw_words: List[int]        # Raw 16-bit words from PLC
    data_type: DataType         # Target data type
    byte_order: ByteOrder       # Byte order
    converted_value: Any = None # Converted value
    display_string: str = ""    # Human-readable string
    
    def __post_init__(self):
        if self.converted_value is None:
            self.converted_value = DataTypeConverter.convert(
                self.raw_words, self.data_type, self.byte_order
            )
            self.display_string = DataTypeConverter.to_string(
                self.converted_value, self.data_type
            )


class DataTypeConverter:
    """
    Converts raw PLC word values to various data types.
    
    PLC registers typically store 16-bit words. This converter handles
    combining multiple words and converting to the target data type.
    """
    
    # Number of words required for each data type
    WORD_COUNT = {
        DataType.WORD: 1,
        DataType.INT16: 1,
        DataType.BCD16: 1,
        DataType.BIT: 1,
        DataType.BOOL: 1,
        DataType.DWORD: 2,
        DataType.INT32: 2,
        DataType.FLOAT: 2,
        DataType.BCD32: 2,
        DataType.QWORD: 4,
        DataType.INT64: 4,
        DataType.DOUBLE: 4,
        DataType.STRING: None,  # Variable
        DataType.RAW: None,     # Variable
    }
    
    @classmethod
    def get_word_count(cls, data_type: DataType, string_length: int = 0) -> int:
        """Get number of words required for a data type"""
        if data_type in (DataType.STRING, DataType.RAW):
            # 2 characters per word for strings
            return (string_length + 1) // 2
        count = cls.WORD_COUNT.get(data_type)
        return count if count is not None else 1
    
    @classmethod
    def convert(
        cls,
        words: List[int],
        data_type: DataType,
        byte_order: ByteOrder = ByteOrder.LITTLE_ENDIAN
    ) -> Any:
        """
        Convert raw words to the specified data type.
        
        Args:
            words: List of 16-bit word values
            data_type: Target data type
            byte_order: Byte order for multi-byte values
        
        Returns:
            Converted value in the appropriate Python type
        """
        if not words:
            return None
        
        # Get bytes from words
        raw_bytes = cls._words_to_bytes(words, byte_order)
        
        try:
            if data_type == DataType.WORD:
                return words[0] & 0xFFFF
            
            elif data_type == DataType.INT16:
                return cls._to_signed16(words[0])
            
            elif data_type == DataType.DWORD:
                return cls._bytes_to_uint32(raw_bytes, byte_order)
            
            elif data_type == DataType.INT32:
                return cls._bytes_to_int32(raw_bytes, byte_order)
            
            elif data_type == DataType.QWORD:
                return cls._bytes_to_uint64(raw_bytes, byte_order)
            
            elif data_type == DataType.INT64:
                return cls._bytes_to_int64(raw_bytes, byte_order)
            
            elif data_type == DataType.FLOAT:
                return cls._bytes_to_float(raw_bytes, byte_order)
            
            elif data_type == DataType.DOUBLE:
                return cls._bytes_to_double(raw_bytes, byte_order)
            
            elif data_type == DataType.BCD16:
                return cls._bcd16_to_int(words[0])
            
            elif data_type == DataType.BCD32:
                return cls._bcd32_to_int(words[:2], byte_order)
            
            elif data_type == DataType.STRING:
                return cls._words_to_string(words)
            
            elif data_type == DataType.RAW:
                return raw_bytes.hex().upper()
            
            elif data_type in (DataType.BIT, DataType.BOOL):
                return bool(words[0] & 1)
            
            else:
                return words[0]
                
        except Exception:
            return None
    
    @classmethod
    def _words_to_bytes(
        cls,
        words: List[int],
        byte_order: ByteOrder
    ) -> bytes:
        """Convert word list to bytes"""
        result = bytearray()
        
        # Handle word swap
        if byte_order in (ByteOrder.LITTLE_ENDIAN_WORD_SWAP, 
                          ByteOrder.BIG_ENDIAN_WORD_SWAP):
            # Swap word pairs
            swapped = []
            for i in range(0, len(words), 2):
                if i + 1 < len(words):
                    swapped.extend([words[i + 1], words[i]])
                else:
                    swapped.append(words[i])
            words = swapped
        
        # Convert words to bytes
        for word in words:
            if byte_order in (ByteOrder.LITTLE_ENDIAN, 
                              ByteOrder.LITTLE_ENDIAN_WORD_SWAP):
                result.extend(struct.pack('<H', word & 0xFFFF))
            else:
                result.extend(struct.pack('>H', word & 0xFFFF))
        
        return bytes(result)
    
    @classmethod
    def _to_signed16(cls, value: int) -> int:
        """Convert unsigned 16-bit to signed"""
        if value >= 0x8000:
            return value - 0x10000
        return value
    
    @classmethod
    def _bytes_to_uint32(cls, data: bytes, byte_order: ByteOrder) -> int:
        """Convert 4 bytes to unsigned 32-bit integer"""
        if len(data) < 4:
            data = data + b'\x00' * (4 - len(data))
        
        if byte_order in (ByteOrder.LITTLE_ENDIAN, 
                          ByteOrder.LITTLE_ENDIAN_WORD_SWAP):
            return struct.unpack('<I', data[:4])[0]
        else:
            return struct.unpack('>I', data[:4])[0]
    
    @classmethod
    def _bytes_to_int32(cls, data: bytes, byte_order: ByteOrder) -> int:
        """Convert 4 bytes to signed 32-bit integer"""
        if len(data) < 4:
            data = data + b'\x00' * (4 - len(data))
        
        if byte_order in (ByteOrder.LITTLE_ENDIAN, 
                          ByteOrder.LITTLE_ENDIAN_WORD_SWAP):
            return struct.unpack('<i', data[:4])[0]
        else:
            return struct.unpack('>i', data[:4])[0]
    
    @classmethod
    def _bytes_to_uint64(cls, data: bytes, byte_order: ByteOrder) -> int:
        """Convert 8 bytes to unsigned 64-bit integer"""
        if len(data) < 8:
            data = data + b'\x00' * (8 - len(data))
        
        if byte_order in (ByteOrder.LITTLE_ENDIAN, 
                          ByteOrder.LITTLE_ENDIAN_WORD_SWAP):
            return struct.unpack('<Q', data[:8])[0]
        else:
            return struct.unpack('>Q', data[:8])[0]
    
    @classmethod
    def _bytes_to_int64(cls, data: bytes, byte_order: ByteOrder) -> int:
        """Convert 8 bytes to signed 64-bit integer"""
        if len(data) < 8:
            data = data + b'\x00' * (8 - len(data))
        
        if byte_order in (ByteOrder.LITTLE_ENDIAN, 
                          ByteOrder.LITTLE_ENDIAN_WORD_SWAP):
            return struct.unpack('<q', data[:8])[0]
        else:
            return struct.unpack('>q', data[:8])[0]
    
    @classmethod
    def _bytes_to_float(cls, data: bytes, byte_order: ByteOrder) -> float:
        """Convert 4 bytes to 32-bit float"""
        if len(data) < 4:
            data = data + b'\x00' * (4 - len(data))
        
        if byte_order in (ByteOrder.LITTLE_ENDIAN, 
                          ByteOrder.LITTLE_ENDIAN_WORD_SWAP):
            return struct.unpack('<f', data[:4])[0]
        else:
            return struct.unpack('>f', data[:4])[0]
    
    @classmethod
    def _bytes_to_double(cls, data: bytes, byte_order: ByteOrder) -> float:
        """Convert 8 bytes to 64-bit double"""
        if len(data) < 8:
            data = data + b'\x00' * (8 - len(data))
        
        if byte_order in (ByteOrder.LITTLE_ENDIAN, 
                          ByteOrder.LITTLE_ENDIAN_WORD_SWAP):
            return struct.unpack('<d', data[:8])[0]
        else:
            return struct.unpack('>d', data[:8])[0]
    
    @classmethod
    def _bcd16_to_int(cls, value: int) -> int:
        """Convert 16-bit BCD to integer"""
        result = 0
        multiplier = 1
        
        for _ in range(4):
            digit = value & 0x0F
            if digit > 9:
                return None  # Invalid BCD
            result += digit * multiplier
            multiplier *= 10
            value >>= 4
        
        return result
    
    @classmethod
    def _bcd32_to_int(cls, words: List[int], byte_order: ByteOrder) -> int:
        """Convert 32-bit BCD to integer"""
        if len(words) < 2:
            return None
        
        # Combine words based on byte order
        if byte_order in (ByteOrder.LITTLE_ENDIAN, 
                          ByteOrder.LITTLE_ENDIAN_WORD_SWAP):
            bcd_value = words[0] | (words[1] << 16)
        else:
            bcd_value = words[1] | (words[0] << 16)
        
        result = 0
        multiplier = 1
        
        for _ in range(8):
            digit = bcd_value & 0x0F
            if digit > 9:
                return None  # Invalid BCD
            result += digit * multiplier
            multiplier *= 10
            bcd_value >>= 4
        
        return result
    
    @classmethod
    def _words_to_string(cls, words: List[int]) -> str:
        """Convert words to ASCII string"""
        chars = []
        
        for word in words:
            # Low byte first, then high byte
            low = word & 0xFF
            high = (word >> 8) & 0xFF
            
            # Stop at null terminator
            if low == 0:
                break
            if low >= 32 and low < 127:
                chars.append(chr(low))
            
            if high == 0:
                break
            if high >= 32 and high < 127:
                chars.append(chr(high))
        
        return ''.join(chars)
    
    @classmethod
    def to_string(cls, value: Any, data_type: DataType) -> str:
        """Convert value to human-readable string"""
        if value is None:
            return ""
        
        if data_type == DataType.FLOAT:
            return f"{value:.6f}"
        elif data_type == DataType.DOUBLE:
            return f"{value:.10f}"
        elif data_type in (DataType.BIT, DataType.BOOL):
            return "ON" if value else "OFF"
        elif data_type == DataType.RAW:
            return str(value)
        elif data_type == DataType.STRING:
            return str(value)
        else:
            return str(value)
    
    @classmethod
    def convert_batch(
        cls,
        words: List[int],
        data_type: DataType,
        byte_order: ByteOrder = ByteOrder.LITTLE_ENDIAN,
        count: Optional[int] = None
    ) -> List[Any]:
        """
        Convert a batch of consecutive values.
        
        Args:
            words: List of all words
            data_type: Data type for each value
            byte_order: Byte order
            count: Number of values to convert (None = auto-calculate)
        
        Returns:
            List of converted values
        """
        word_count = cls.get_word_count(data_type)
        
        if word_count is None:
            # Variable-length type, return single value
            return [cls.convert(words, data_type, byte_order)]
        
        if count is None:
            count = len(words) // word_count
        
        results = []
        for i in range(count):
            start = i * word_count
            end = start + word_count
            if end <= len(words):
                value = cls.convert(words[start:end], data_type, byte_order)
                results.append(value)
        
        return results


@dataclass
class DataTypeMapping:
    """Mapping for address range to data type"""
    start_address: int
    end_address: int
    data_type: DataType
    byte_order: ByteOrder = ByteOrder.LITTLE_ENDIAN
    description: str = ""
    
    def contains(self, address: int) -> bool:
        """Check if address is within this mapping"""
        return self.start_address <= address <= self.end_address


class DataTypeManager:
    """
    Manages data type mappings for address ranges.
    
    Allows defining specific data types for address ranges,
    enabling automatic conversion during data collection.
    """
    
    def __init__(self):
        self.mappings: List[DataTypeMapping] = []
        self.default_type: DataType = DataType.WORD
        self.default_byte_order: ByteOrder = ByteOrder.LITTLE_ENDIAN
    
    def add_mapping(self, mapping: DataTypeMapping) -> None:
        """Add a data type mapping"""
        self.mappings.append(mapping)
        # Sort by start address
        self.mappings.sort(key=lambda m: m.start_address)
    
    def get_type_for_address(self, address: int) -> Tuple[DataType, ByteOrder]:
        """Get data type for a specific address"""
        for mapping in self.mappings:
            if mapping.contains(address):
                return mapping.data_type, mapping.byte_order
        return self.default_type, self.default_byte_order
    
    def set_default(self, data_type: DataType, byte_order: Optional[ByteOrder] = None) -> None:
        """Set default data type"""
        self.default_type = data_type
        if byte_order:
            self.default_byte_order = byte_order
    
    def clear(self):
        """Clear all mappings"""
        self.mappings.clear()
    
    @classmethod
    def from_config(cls, config: dict) -> 'DataTypeManager':
        """Create manager from configuration dictionary"""
        manager = cls()
        
        # Set defaults
        if "default_type" in config:
            manager.default_type = DataType(config["default_type"])
        if "default_byte_order" in config:
            manager.default_byte_order = ByteOrder(config["default_byte_order"])
        
        # Add mappings
        for mapping_config in config.get("mappings", []):
            mapping = DataTypeMapping(
                start_address=mapping_config["start"],
                end_address=mapping_config["end"],
                data_type=DataType(mapping_config["type"]),
                byte_order=ByteOrder(mapping_config.get("byte_order", "little")),
                description=mapping_config.get("description", ""),
            )
            manager.add_mapping(mapping)
        
        return manager

