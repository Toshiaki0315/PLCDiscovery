"""
Regression tests for miscellaneous behaviour, found and fixed in code reviews.
"""

import asyncio
import math
from pathlib import Path

import pytest
import yaml

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


ROOT = Path(__file__).resolve().parent.parent


def test_lint_tools_are_pinned_to_the_versions_ci_uses():
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    pins = ("black==26.5.1", "isort==6.0.1", "flake8==7.3.0", "mypy==1.18.1")
    for name in ("requirements-dev.txt", "pyproject.toml"):
        text = (ROOT / name).read_text(encoding="utf-8")
        for pin in pins:
            assert pin in ci and pin in text, f"{pin} in {name}"


def test_pytest_is_configured_once_with_a_time_limit():
    assert "timeout = 120" in (ROOT / "pytest.ini").read_text(encoding="utf-8")
    assert "[tool.pytest.ini_options]" not in (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "pytest-timeout" in (ROOT / "requirements-dev.txt").read_text(encoding="utf-8")


def test_every_ci_job_has_a_time_limit():
    lines = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8").splitlines()
    jobs = [i for i, line in enumerate(lines) if line.strip() == "runs-on: ubuntu-latest"]
    assert len(jobs) >= 6
    for index in jobs:
        assert any("timeout-minutes:" in line for line in lines[index + 1 : index + 4]), lines[index - 1]


def test_wait_for_keeps_a_cancellation_that_arrives_as_the_result_does():
    from plc_discovery.utils import wait_for

    async def body():
        future = asyncio.get_running_loop().create_future()
        asyncio.get_running_loop().call_soon(future.set_result, "answer")
        await wait_for(future, 2)
        return "went on"  # asyncio.wait_for of Python 3.10 / 3.11 returned here: the stop was ignored

    async def run():
        task = asyncio.ensure_future(body())
        await asyncio.sleep(0)  # body is waiting
        await asyncio.sleep(0)  # the result is there, body's wake-up is scheduled
        task.cancel()
        try:
            return await task
        except asyncio.CancelledError:
            return "stopped"

    assert asyncio.run(run()) == "stopped"


def test_wait_for_times_out_and_returns_results_like_asyncio():
    from plc_discovery.utils import wait_for

    async def run():
        cleaned = []

        async def slow():
            try:
                await asyncio.sleep(10)
            finally:
                cleaned.append(True)

        async def quick():
            return 7

        async def failing():
            raise ValueError("bad frame")

        with pytest.raises(asyncio.TimeoutError):
            await wait_for(slow(), 0.05)
        with pytest.raises(ValueError, match="bad frame"):
            await wait_for(failing(), 1)
        return await wait_for(quick(), 1), cleaned

    assert asyncio.run(run()) == (7, [True])  # the timed-out coroutine was cancelled and ran its cleanup


def test_check_bat_does_not_run_the_checks_again_after_a_failure():
    lines = (ROOT / "scripts" / "check.bat").read_text(encoding="utf-8").splitlines()
    commands = [line for line in lines if "check.py" in line and not line.lower().startswith("rem")]
    assert len(commands) == 3  # .venv, py, python: one each
    for line in commands:
        # "a && (run) || (run)" runs the second one when the first run fails
        assert "||" not in line and "&&" not in line
    # Each run is followed by the exit with its result
    for i, line in enumerate(lines):
        if line in commands:
            assert lines[i + 1].strip().lower() == "exit /b %errorlevel%"


def test_codecov_upload_runs_only_with_its_token():
    """Without CODECOV_TOKEN the upload failed in every run ("Token required")"""
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["unit-test"]["steps"]
    (upload,) = [s for s in steps if "codecov/codecov-action" in s.get("uses", "")]
    (check,) = [s for s in steps if s.get("id") == "codecov"]
    assert steps.index(check) < steps.index(upload)
    assert upload["if"] == "steps.codecov.outputs.enabled == 'true'"
    assert upload["with"]["token"] == "${{ secrets.CODECOV_TOKEN }}"
    assert check["env"]["CODECOV_TOKEN"] == "${{ secrets.CODECOV_TOKEN }}"
    assert 'echo "enabled=true" >> "$GITHUB_OUTPUT"' in check["run"]
