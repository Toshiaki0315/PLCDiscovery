"""
Regression tests for data type conversion, found and fixed in code reviews.
"""

import json
import sys
from pathlib import Path

import pytest

import plc_scanner
from plc_discovery.config import DataPoint, StatusCode
from plc_discovery.config_loader import ConfigLoader
from plc_discovery.data_types import ByteOrder, DataType, DataTypeConverter, DataTypeManager, DataTypeMapping

WORDS = [0x4142, 0x4344]  # bytes 41 42 43 44 as Siemens/Omron store "ABCD"


def _args(monkeypatch, *argv):
    monkeypatch.setattr(sys, "argv", ["plc_scanner.py", *argv])
    return plc_scanner.parse_args()


def _loader(tmp_path, text):
    path = tmp_path / "cfg.yaml"
    path.write_text(text, encoding="utf-8")
    loader = ConfigLoader(str(path))
    loader.load()
    return loader


MINIMAL = "scan:\n  mode: discover\n"


def ok(address, value):
    return DataPoint(address, value, f"0x{value:04X}", StatusCode.OK)


def failed(address):
    return DataPoint(address, status=StatusCode.NG_TIMEOUT)


def converted(points):
    return [(dp.address, dp.converted_value) for dp in points if dp.converted_value is not None]


FLOATS = {1.0: (0x0000, 0x3F80), 2.0: (0x0000, 0x4000), 3.0: (0x0000, 0x4040), 4.0: (0x0000, 0x4080)}


def float_words(start, *values):
    points = []
    for n, v in enumerate(values):
        lo, hi = FLOATS[v]
        points += [ok(f"D{start + 2 * n}", lo), ok(f"D{start + 2 * n + 1}", hi)]
    return points


ROOT = Path(__file__).resolve().parent.parent


def string_words(text, n_words):
    padded = text.ljust(n_words * 2, "\0")
    return [ord(padded[i]) | (ord(padded[i + 1]) << 8) for i in range(0, n_words * 2, 2)]


def points(start, words, prefix="D"):
    return [DataPoint(f"{prefix}{start + i}", w, f"0x{w:04X}", StatusCode.OK) for i, w in enumerate(words)]


@pytest.mark.parametrize(
    "byte_order, text",
    [
        (ByteOrder.LITTLE_ENDIAN, "BADC"),  # low byte first (Mitsubishi, Keyence): unchanged
        (ByteOrder.BIG_ENDIAN, "ABCD"),  # previously "BADC"
        (ByteOrder.LITTLE_ENDIAN_WORD_SWAP, "ABCD"),
        (ByteOrder.BIG_ENDIAN_WORD_SWAP, "BADC"),
    ],
)
def test_string_follows_byte_order(byte_order, text):
    assert DataTypeConverter.convert(WORDS, DataType.STRING, byte_order) == text


def test_big_endian_string_stops_at_nul():
    assert DataTypeConverter.convert([0x4142, 0x4300, 0x4445], DataType.STRING, ByteOrder.BIG_ENDIAN) == "ABC"


def test_mapping_without_byte_order_uses_default():
    manager = DataTypeManager.from_config(
        {
            "default_byte_order": "big",
            "mappings": [
                {"start": 0, "end": 1, "type": "FLOAT"},
                {"start": 2, "end": 3, "type": "FLOAT", "byte_order": "little"},
            ],
        }
    )
    assert [m.byte_order for m in manager.mappings] == [ByteOrder.BIG_ENDIAN, ByteOrder.LITTLE_ENDIAN]


def test_big_endian_float_mapping_value():
    manager = DataTypeManager.from_config(
        {
            "default_byte_order": "big",
            "mappings": [{"start": 0, "end": 1, "type": "FLOAT"}],
        }
    )
    words = [0x3F80, 0x0000]  # 1.0 high word first
    points = [DataPoint(f"D{i}", w, f"0x{w:04X}", StatusCode.OK) for i, w in enumerate(words)]
    first = plc_scanner.apply_data_type_conversion(points, None, ByteOrder.LITTLE_ENDIAN, manager)[0]
    assert first.converted_value == 1.0  # previously 2.3e-41 (read as little)


def test_names_are_case_insensitive():
    manager = DataTypeManager.from_config(
        {
            "default_type": "dword",
            "default_byte_order": "BIG",
            "mappings": [{"start": 0, "end": 1, "type": "float", "byte_order": "Little_Swap", "device": "d"}],
        }
    )
    assert manager.default_type == DataType.DWORD and manager.default_byte_order == ByteOrder.BIG_ENDIAN
    (mapping,) = manager.mappings
    assert (mapping.data_type, mapping.byte_order, mapping.device) == (
        DataType.FLOAT,
        ByteOrder.LITTLE_ENDIAN_WORD_SWAP,
        "D",
    )


def test_type_mapping_file_error_names_the_file(tmp_path):
    path = tmp_path / "types.json"
    path.write_text(json.dumps({"mappings": [{"start": 0, "end": 1, "type": "REAL"}]}))
    with pytest.raises(ValueError, match=r"types\.json\.mappings\[0\]\.type"):
        plc_scanner.load_type_mapping(str(path))


def test_config_without_data_types_adds_no_conversion(monkeypatch, tmp_path):
    """Defaults filled in by the loader are not an explicit conversion request"""
    assert plc_scanner.resolve_data_types(_args(monkeypatch), _loader(tmp_path, MINIMAL)) == (
        None,
        ByteOrder.LITTLE_ENDIAN,
        None,
    )


@pytest.mark.parametrize(
    "value,float_text,double_text",
    [
        (23.5, "23.5", "23.5"),
        (1e30, "1e+30", "1e+30"),
        (0.000012345, "1.2345e-05", "1.2345e-05"),
        (-1.46e-12, "-1.46e-12", "-1.46e-12"),
        (123456.789, "123456.8", "123456.789"),
    ],
)
def test_float_display_uses_significant_digits(value, float_text, double_text):
    assert DataTypeConverter.to_string(value, DataType.FLOAT) == float_text
    assert DataTypeConverter.to_string(value, DataType.DOUBLE) == double_text


class TestAlignment:

    def test_failed_word_does_not_shift_following_values(self):
        points = float_words(100, 1.0, 2.0, 3.0, 4.0)
        points[4] = failed("D104")  # first word of 3.0
        result = plc_scanner.apply_data_type_conversion(points, DataType.FLOAT, ByteOrder.LITTLE_ENDIAN)
        assert converted(result) == [("D100", 1.0), ("D102", 2.0), ("D106", 4.0)]
        assert result[5].display_value == "(part of D104, incomplete)"
        assert [dp.address for dp in result] == [dp.address for dp in points]  # nothing dropped

    def test_failed_second_word_marks_value_incomplete(self):
        points = float_words(100, 1.0, 2.0)
        points[1] = failed("D101")
        result = plc_scanner.apply_data_type_conversion(points, DataType.FLOAT, ByteOrder.LITTLE_ENDIAN)
        assert converted(result) == [("D102", 2.0)]
        assert result[0].display_value.startswith("(incomplete FLOAT")

    def test_mapping_aligned_to_mapping_start(self):
        manager = DataTypeManager.from_config({"mappings": [{"start": 100, "end": 199, "type": "FLOAT"}]})
        points = float_words(100, 1.0, 2.0)[1:]  # range starts at D101
        result = plc_scanner.apply_data_type_conversion(points, None, ByteOrder.LITTLE_ENDIAN, manager)
        assert converted(result) == [("D102", 2.0)]
        assert result[0].display_value == "(part of D100, incomplete)"

    def test_without_mapping_aligned_to_range_start(self):
        points = float_words(101, 1.0, 2.0)  # requested range starts at D101
        result = plc_scanner.apply_data_type_conversion(points, DataType.FLOAT, ByteOrder.LITTLE_ENDIAN)
        assert converted(result) == [("D101", 1.0), ("D103", 2.0)]

    def test_each_range_has_its_own_alignment(self):
        points = float_words(0, 1.0) + float_words(51, 2.0)  # two separate ranges
        result = plc_scanner.apply_data_type_conversion(points, DataType.FLOAT, ByteOrder.LITTLE_ENDIAN)
        assert converted(result) == [("D0", 1.0), ("D51", 2.0)]


class TestDeviceAwareMappings:

    def test_mapping_without_device_skips_bit_devices(self):
        manager = DataTypeManager.from_config({"mappings": [{"start": 100, "end": 199, "type": "FLOAT"}]})
        result = plc_scanner.apply_data_type_conversion(
            [ok("M100", 1), ok("M101", 0)], None, ByteOrder.LITTLE_ENDIAN, manager
        )
        assert all(dp.data_type != "FLOAT" for dp in result)

    def test_mapping_with_device_only_applies_to_that_device(self):
        manager = DataTypeManager.from_config(
            {
                "mappings": [
                    {"device": "HR", "start": 0, "end": 1, "type": "FLOAT"},
                ]
            }
        )
        d_points = plc_scanner.apply_data_type_conversion(float_words(0, 1.0), None, ByteOrder.LITTLE_ENDIAN, manager)
        # D0-D1 are not HR: only the default WORD type applies
        assert [dp.data_type for dp in d_points] == ["WORD", "WORD"]
        hr_points = [ok("HR0", 0x0000), ok("HR1", 0x3F80)]
        assert converted(plc_scanner.apply_data_type_conversion(hr_points, None, ByteOrder.LITTLE_ENDIAN, manager)) == [
            ("HR0", 1.0)
        ]

    def test_explicit_bit_device_mapping_allowed_for_single_word(self):
        mapping = DataTypeMapping(0, 10, DataType.BOOL, device="M")
        assert mapping.contains(5, "M") and not mapping.contains(5, "D")

    def test_multi_word_default_type_never_applied_to_bits(self):
        result = plc_scanner.apply_data_type_conversion(
            [ok("M0", 1), ok("M1", 1)], DataType.FLOAT, ByteOrder.LITTLE_ENDIAN
        )
        assert converted(result) == [] and all(dp.data_type is None for dp in result)

    def test_legacy_lookup_without_device(self):
        manager = DataTypeManager.from_config({"mappings": [{"start": 100, "end": 199, "type": "FLOAT"}]})
        assert manager.get_type_for_address(150) == (DataType.FLOAT, ByteOrder.LITTLE_ENDIAN)


class TestStrings:

    def test_mapping_with_length(self):
        manager = DataTypeManager.from_config(
            {
                "mappings": [
                    {"device": "D", "start": 1000, "end": 1019, "type": "STRING", "length": 10},
                ]
            }
        )
        words = string_words("PRODUCT-A1", 10) + string_words("ITEM-B2", 10)
        result = plc_scanner.apply_data_type_conversion(points(1000, words), None, ByteOrder.LITTLE_ENDIAN, manager)
        assert [(d.address, d.converted_value) for d in result if d.converted_value] == [
            ("D1000", "PRODUCT-A1"),
            ("D1010", "ITEM-B2"),
        ]
        assert len(result) == 20 and result[1].display_value == "(part of D1000)"

    def test_mapping_without_length_is_one_value(self):
        manager = DataTypeManager.from_config({"mappings": [{"start": 0, "end": 3, "type": "STRING"}]})
        result = plc_scanner.apply_data_type_conversion(
            points(0, string_words("ABCDEF", 4)), None, ByteOrder.LITTLE_ENDIAN, manager
        )
        assert result[0].converted_value == "ABCDEF"

    def test_cli_data_type_string_uses_whole_range(self):
        result = plc_scanner.apply_data_type_conversion(
            points(0, string_words("HELLO", 4)), DataType.STRING, ByteOrder.LITTLE_ENDIAN
        )
        assert result[0].converted_value == "HELLO"

    def test_failed_word_makes_string_incomplete(self):
        pts = points(0, string_words("HELLO", 4))
        pts[2] = DataPoint("D2", status=StatusCode.NG_TIMEOUT)
        result = plc_scanner.apply_data_type_conversion(pts, DataType.STRING, ByteOrder.LITTLE_ENDIAN)
        assert all(d.converted_value is None for d in result)
        assert result[0].display_value.startswith("(incomplete STRING")

    def test_raw_hex(self):
        result = plc_scanner.apply_data_type_conversion(points(0, [0x1234, 0xABCD]), DataType.RAW, ByteOrder.BIG_ENDIAN)
        assert result[0].converted_value == "1234ABCD"

    def test_example_mapping_file(self):
        manager = DataTypeManager.from_config(
            json.loads((ROOT / "type_mapping.example.json").read_text(encoding="utf-8"))
        )
        (mapping,) = [m for m in manager.mappings if m.data_type == DataType.STRING]
        assert mapping.words_per_value() == 10
