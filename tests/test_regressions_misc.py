"""
Regression tests for miscellaneous behaviour, found and fixed in code reviews.
"""

import math

import pytest

from plc_discovery import audit_log
from plc_discovery.config import MAX_RANGE_POINTS, clean_device_text, range_size_error
from plc_discovery.discovery import MAX_PROBE_THREADS
from plc_discovery.report import json_safe
from plc_discovery.utils import address_sort_key, ip_range_error, parse_ip_range, sorted_addresses

EVIL = "m\x1b]0;pwned\x07\x1b[2J\x9b31m"


def test_clean_device_text():
    assert clean_device_text(EVIL) == "m]0;pwned[2J31m"
    assert clean_device_text(" NJ501\r\n") == "NJ501"
    assert clean_device_text(None) is None


@pytest.mark.parametrize(
    "ip_range, ok",
    [
        ("192.168.1.0/24", True),
        ("10.0.0.0/16", True),  # 65,534 hosts
        ("10.0.0.0/15", False),
        ("10.0.0.0/8", False),  # 16.7 million hosts (a /24 typo)
        ("10.0.0.0-10.1.0.0", False),  # 65,537 hosts
        ("10.0.0.1-10.0.255.255", True),
        ("192.168.1.5", True),
        ("192.168.1.0/33", False),
    ],
)
def test_ip_range_error(ip_range, ok):
    assert (ip_range_error(ip_range) is None) is ok


def test_parse_ip_range_refuses_huge_range():
    assert parse_ip_range("10.0.0.0/8") == []
    assert len(parse_ip_range("10.0.0.0/16")) == 65534
    assert parse_ip_range("10.0.0.0/31") == ["10.0.0.0", "10.0.0.1"]


def test_addresses_sorted_by_device_and_number():
    assert sorted_addresses({"D5003", "D17", "M0", "D5000", "DM2", "x?"}) == [
        "D17",
        "D5000",
        "D5003",
        "DM2",
        "M0",
        "x?",
    ]
    assert address_sort_key("D9") < address_sort_key("D10")


def test_range_size_error():
    assert range_size_error(0, MAX_RANGE_POINTS - 1) is None
    assert "at most" in range_size_error(0, MAX_RANGE_POINTS)


def test_audit_logger_reinit_uses_new_file(tmp_path):
    audit_log.get_audit_logger().log_error("before init")
    first, second = tmp_path / "a1.log", tmp_path / "a2.log"
    audit_log.init_audit_logger(str(first)).log_error("first")
    audit_log.close_audit_logger()
    audit_log.init_audit_logger(str(second)).log_error("second")
    audit_log.close_audit_logger()
    assert "first" in first.read_text(encoding="utf-8")
    assert "second" in second.read_text(encoding="utf-8")


def test_json_safe():
    assert json_safe({"a": [1.5, math.nan, {"b": math.inf}], "c": "NaN"}) == {"a": [1.5, None, {"b": None}], "c": "NaN"}


def test_pool_size_bound():
    assert MAX_PROBE_THREADS == 64
