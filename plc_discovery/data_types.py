"""
Data Type Conversion Module

Provides conversion between raw PLC data and various data types.
Supports WORD, DWORD, FLOAT, DOUBLE, STRING, BCD, and signed variants.
"""

import struct
from dataclasses import dataclass
from enum import Enum
from typing import Any, List, Optional, Tuple, Type, TypeVar


class DataType(Enum):
    """Supported data types for PLC values"""

    # Unsigned integers
    WORD = "WORD"  # 16-bit unsigned integer (1 word)
    DWORD = "DWORD"  # 32-bit unsigned integer (2 words)
    QWORD = "QWORD"  # 64-bit unsigned integer (4 words)

    # Signed integers
    INT16 = "INT16"  # 16-bit signed integer (1 word)
    INT32 = "INT32"  # 32-bit signed integer (2 words)
    INT64 = "INT64"  # 64-bit signed integer (4 words)

    # Floating point
    FLOAT = "FLOAT"  # 32-bit IEEE 754 float (2 words)
    DOUBLE = "DOUBLE"  # 64-bit IEEE 754 double (4 words)

    # Special formats
    BCD16 = "BCD16"  # 16-bit BCD (4 digits)
    BCD32 = "BCD32"  # 32-bit BCD (8 digits)

    # String/raw
    STRING = "STRING"  # ASCII string (variable length)
    RAW = "RAW"  # Raw bytes (no conversion)

    # Boolean (bit)
    BIT = "BIT"  # Single bit value
    BOOL = "BOOL"  # Boolean (same as BIT)


class ByteOrder(Enum):
    """
    Order of multi-word values.

    Each PLC register is a 16-bit word ``AB`` (A = high byte, B = low byte).
    For a 32-bit value made of words ``AB`` (high) and ``CD`` (low):

        LITTLE_ENDIAN            "little"       CDAB  low word first (Mitsubishi, Keyence, Omron)
        BIG_ENDIAN               "big"          ABCD  high word first (Modbus standard, Siemens)
        LITTLE_ENDIAN_WORD_SWAP  "little_swap"  DCBA  low word first, bytes swapped in each word
        BIG_ENDIAN_WORD_SWAP     "big_swap"     BADC  high word first, bytes swapped in each word

    The "_swap" names are kept for configuration compatibility; they swap
    the two bytes inside every word.
    """

    LITTLE_ENDIAN = "little"
    BIG_ENDIAN = "big"
    LITTLE_ENDIAN_WORD_SWAP = "little_swap"
    BIG_ENDIAN_WORD_SWAP = "big_swap"


@dataclass
class TypedValue:
    """Value with type information"""

    raw_words: List[int]  # Raw 16-bit words from PLC
    data_type: DataType  # Target data type
    byte_order: ByteOrder  # Byte order
    converted_value: Any = None  # Converted value
    display_string: str = ""  # Human-readable string

    def __post_init__(self):
        if self.converted_value is None:
            self.converted_value = DataTypeConverter.convert(self.raw_words, self.data_type, self.byte_order)
            self.display_string = DataTypeConverter.to_string(self.converted_value, self.data_type)


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
        DataType.RAW: None,  # Variable
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
    def convert(cls, words: List[int], data_type: DataType, byte_order: ByteOrder = ByteOrder.LITTLE_ENDIAN) -> Any:
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
                return cls._bytes_to_string(raw_bytes)

            elif data_type == DataType.RAW:
                return raw_bytes.hex().upper()

            elif data_type in (DataType.BIT, DataType.BOOL):
                return bool(words[0] & 1)

            else:
                return words[0]

        except Exception:
            return None

    @classmethod
    def _is_little(cls, byte_order: ByteOrder) -> bool:
        """True when the low word comes first"""
        return byte_order in (ByteOrder.LITTLE_ENDIAN, ByteOrder.LITTLE_ENDIAN_WORD_SWAP)

    @classmethod
    def _is_byte_swapped(cls, byte_order: ByteOrder) -> bool:
        """True when the two bytes inside each word are swapped"""
        return byte_order in (ByteOrder.LITTLE_ENDIAN_WORD_SWAP, ByteOrder.BIG_ENDIAN_WORD_SWAP)

    @classmethod
    def _swap_word_bytes(cls, word: int) -> int:
        return ((word & 0xFF) << 8) | ((word >> 8) & 0xFF)

    @classmethod
    def _words_to_bytes(cls, words: List[int], byte_order: ByteOrder) -> bytes:
        """
        Convert word list to bytes in the struct format matching byte_order.

        The result is unpacked with '<' for little orders and '>' for big
        orders by the _bytes_to_* helpers.
        """
        result = bytearray()
        little = cls._is_little(byte_order)
        swapped = cls._is_byte_swapped(byte_order)

        for word in words:
            word &= 0xFFFF
            if swapped:
                word = cls._swap_word_bytes(word)
            result.extend(struct.pack("<H" if little else ">H", word))

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
            data = data + b"\x00" * (4 - len(data))

        if byte_order in (ByteOrder.LITTLE_ENDIAN, ByteOrder.LITTLE_ENDIAN_WORD_SWAP):
            return int(struct.unpack("<I", data[:4])[0])
        else:
            return int(struct.unpack(">I", data[:4])[0])

    @classmethod
    def _bytes_to_int32(cls, data: bytes, byte_order: ByteOrder) -> int:
        """Convert 4 bytes to signed 32-bit integer"""
        if len(data) < 4:
            data = data + b"\x00" * (4 - len(data))

        if byte_order in (ByteOrder.LITTLE_ENDIAN, ByteOrder.LITTLE_ENDIAN_WORD_SWAP):
            return int(struct.unpack("<i", data[:4])[0])
        else:
            return int(struct.unpack(">i", data[:4])[0])

    @classmethod
    def _bytes_to_uint64(cls, data: bytes, byte_order: ByteOrder) -> int:
        """Convert 8 bytes to unsigned 64-bit integer"""
        if len(data) < 8:
            data = data + b"\x00" * (8 - len(data))

        if byte_order in (ByteOrder.LITTLE_ENDIAN, ByteOrder.LITTLE_ENDIAN_WORD_SWAP):
            return int(struct.unpack("<Q", data[:8])[0])
        else:
            return int(struct.unpack(">Q", data[:8])[0])

    @classmethod
    def _bytes_to_int64(cls, data: bytes, byte_order: ByteOrder) -> int:
        """Convert 8 bytes to signed 64-bit integer"""
        if len(data) < 8:
            data = data + b"\x00" * (8 - len(data))

        if byte_order in (ByteOrder.LITTLE_ENDIAN, ByteOrder.LITTLE_ENDIAN_WORD_SWAP):
            return int(struct.unpack("<q", data[:8])[0])
        else:
            return int(struct.unpack(">q", data[:8])[0])

    @classmethod
    def _bytes_to_float(cls, data: bytes, byte_order: ByteOrder) -> float:
        """Convert 4 bytes to 32-bit float"""
        if len(data) < 4:
            data = data + b"\x00" * (4 - len(data))

        if byte_order in (ByteOrder.LITTLE_ENDIAN, ByteOrder.LITTLE_ENDIAN_WORD_SWAP):
            return float(struct.unpack("<f", data[:4])[0])
        else:
            return float(struct.unpack(">f", data[:4])[0])

    @classmethod
    def _bytes_to_double(cls, data: bytes, byte_order: ByteOrder) -> float:
        """Convert 8 bytes to 64-bit double"""
        if len(data) < 8:
            data = data + b"\x00" * (8 - len(data))

        if byte_order in (ByteOrder.LITTLE_ENDIAN, ByteOrder.LITTLE_ENDIAN_WORD_SWAP):
            return float(struct.unpack("<d", data[:8])[0])
        else:
            return float(struct.unpack(">d", data[:8])[0])

    @classmethod
    def _bcd16_to_int(cls, value: int) -> Optional[int]:
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
    def _bcd32_to_int(cls, words: List[int], byte_order: ByteOrder) -> Optional[int]:
        """Convert 32-bit BCD to integer"""
        if len(words) < 2:
            return None

        w0, w1 = words[0] & 0xFFFF, words[1] & 0xFFFF
        if cls._is_byte_swapped(byte_order):
            w0, w1 = cls._swap_word_bytes(w0), cls._swap_word_bytes(w1)

        # Combine words based on word order
        if cls._is_little(byte_order):
            bcd_value = w0 | (w1 << 16)
        else:
            bcd_value = w1 | (w0 << 16)

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
    def _bytes_to_string(cls, data: bytes) -> str:
        """
        Convert bytes (already in memory order for the byte order) to ASCII.

        The character order inside each word follows the byte order like
        every other type: "little" = low byte first (Mitsubishi, Keyence),
        "big" = high byte first (Siemens, Omron, most Modbus devices); the
        "_swap" orders reverse that. Reading stops at the first NUL;
        non-printable bytes are skipped.
        """
        chars = []
        for byte in data:
            if byte == 0:
                break
            if 32 <= byte < 127:
                chars.append(chr(byte))
        return "".join(chars)

    @classmethod
    def _words_to_string(cls, words: List[int], byte_order: ByteOrder = ByteOrder.LITTLE_ENDIAN) -> str:
        """Convert words to ASCII string (see _bytes_to_string)"""
        return cls._bytes_to_string(cls._words_to_bytes(words, byte_order))

    @classmethod
    def to_string(cls, value: Any, data_type: DataType) -> str:
        """Convert value to human-readable string"""
        if value is None:
            return ""

        if data_type == DataType.FLOAT:
            # Significant digits (float32 holds ~7): fixed decimals showed
            # 1e30 as a 37-digit number and 1.2e-5 as 0.000012
            return f"{value:.7g}"
        elif data_type == DataType.DOUBLE:
            return f"{value:.15g}"
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
        count: Optional[int] = None,
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


# Types whose size is not fixed by the type itself
VARIABLE_LENGTH_TYPES = frozenset({DataType.STRING, DataType.RAW})

# Bit devices: multi-word types are never applied to them, and mappings
# without an explicit device do not apply to them
BIT_DEVICES = frozenset({"M", "X", "Y", "B", "SM"})


@dataclass
class DataTypeMapping:
    """
    Mapping for an address range to a data type.

    ``device`` (e.g. "D", "DM", "HR") restricts the mapping to one device
    type. A mapping without a device applies to word devices only, so a
    "100-199 = FLOAT" mapping is never applied to M100-M199.
    Multi-word values are aligned to ``start_address``: with FLOAT at
    100-199 the words are paired as 100-101, 102-103, ...
    STRING / RAW values span ``length`` words (default: the whole range).
    """

    def words_per_value(self) -> int:
        """Number of words that make up one value of this mapping"""
        if self.data_type in VARIABLE_LENGTH_TYPES:
            return self.length or (self.end_address - self.start_address + 1)
        return DataTypeConverter.get_word_count(self.data_type)

    start_address: int
    end_address: int
    data_type: DataType
    byte_order: ByteOrder = ByteOrder.LITTLE_ENDIAN
    description: str = ""
    device: Optional[str] = None
    # Words per value for variable-length types (STRING, RAW). Default: the
    # whole mapping range is one value. E.g. 100 words with length 10 =
    # ten 20-character strings.
    length: Optional[int] = None

    def contains(self, address: int, device: Optional[str] = None) -> bool:
        """Check if address (of the given device type) is within this mapping"""
        if not self.start_address <= address <= self.end_address:
            return False
        if device is None:
            return True  # legacy call without device information
        device = device.upper()
        if self.device:
            return self.device.upper() == device
        return device not in BIT_DEVICES


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

    def get_mapping_for_address(self, address: int, device: Optional[str] = None) -> Optional[DataTypeMapping]:
        """Get the mapping covering an address (None if only the default applies)"""
        for mapping in self.mappings:
            if mapping.contains(address, device):
                return mapping
        return None

    def get_type_for_address(self, address: int, device: Optional[str] = None) -> Tuple[DataType, ByteOrder]:
        """Get data type for a specific address"""
        mapping = self.get_mapping_for_address(address, device)
        if mapping:
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
    def from_config(cls, config: Optional[dict], prefix: str = "data_types") -> "DataTypeManager":
        """
        Create manager from configuration dictionary.

        Type and byte order names are case-insensitive. A mapping without
        ``byte_order`` uses ``default_byte_order``.

        Raises:
            ValueError: with the offending key (e.g. "data_types.mappings[0].end")
        """
        manager = cls()
        if config is None:
            return manager
        if not isinstance(config, dict):
            raise ValueError(f"{prefix} must be a mapping")

        if config.get("default_type") is not None:
            manager.default_type = _parse_enum(DataType, config["default_type"], f"{prefix}.default_type")
        if config.get("default_byte_order") is not None:
            manager.default_byte_order = _parse_enum(
                ByteOrder, config["default_byte_order"], f"{prefix}.default_byte_order"
            )

        mappings = config.get("mappings") or []
        if not isinstance(mappings, list):
            raise ValueError(f"{prefix}.mappings must be a list")
        for i, mapping_config in enumerate(mappings):
            where = f"{prefix}.mappings[{i}]"
            if not isinstance(mapping_config, dict):
                raise ValueError(f"{where} must be a mapping")
            for key in ("start", "end", "type"):
                if mapping_config.get(key) is None:
                    raise ValueError(f"{where}.{key} is required")
            start, end = mapping_config["start"], mapping_config["end"]
            for key, value in (("start", start), ("end", end)):
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise ValueError(f"{where}.{key} must be an integer >= 0, got {value!r}")
            if start > end:
                raise ValueError(f"{where}: start must be <= end")
            length = mapping_config.get("length")
            if length is not None and (isinstance(length, bool) or not isinstance(length, int) or length < 1):
                raise ValueError(f"{where}.length must be an integer >= 1, got {length!r}")
            byte_order = mapping_config.get("byte_order")
            device = mapping_config.get("device")
            mapping = DataTypeMapping(
                start_address=start,
                end_address=end,
                data_type=_parse_enum(DataType, mapping_config["type"], f"{where}.type"),
                byte_order=(
                    _parse_enum(ByteOrder, byte_order, f"{where}.byte_order")
                    if byte_order is not None
                    else manager.default_byte_order
                ),
                description=mapping_config.get("description", ""),
                device=str(device).upper() if device else None,
                length=length,
            )
            manager.add_mapping(mapping)

        return manager


_E = TypeVar("_E", bound=Enum)


def _parse_enum(enum_cls: Type[_E], value: Any, where: str) -> _E:
    """Case-insensitive enum lookup by value with a readable error"""
    text = str(value).strip()
    for member in enum_cls:
        if member.value.lower() == text.lower():
            return member
    allowed = ", ".join(m.value for m in enum_cls)
    raise ValueError(f"{where}: unknown value {value!r} (allowed: {allowed})")
