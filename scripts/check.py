#!/usr/bin/env python3
"""
Run the checks of the CI workflow (.github/workflows/ci.yml) on this machine
and say which passed and which failed - before a push, not after it.

    python scripts/check.py                 # tools, lint, unit and integration tests
    python scripts/check.py --lint          # tools and lint only (seconds)
    python scripts/check.py --no-integration

Every step runs even when an earlier one failed, and the summary at the end
lists each with its result: a lint failure cannot hide behind a later
"done" line. Exit code 0 only when every step passed.

The commands are the CI's (tests/test_check_script.py keeps them in step
with ci.yml); they run with this Python, so use the environment the project
is developed in (e.g. .venv with requirements-dev.txt installed).
"""

import argparse
import importlib.metadata
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional

ROOT = Path(__file__).resolve().parent.parent

# Entry-point scripts at the repository root, checked like the package
# (the CI's TOP_LEVEL)
TOP_LEVEL = ["plc_scanner.py", "plc_gui.py", "plc_gui_settings.py", "plc_gui_tags.py"]

# The lint steps of the CI's code-quality job: (name, module, arguments)
LINT_STEPS = [
    (
        "flake8",
        "flake8",
        ["plc_discovery", "tests", "simulators", "scripts", *TOP_LEVEL]
        + ["--max-line-length=120", "--ignore=E501,W503,E402,E203,E704"],
    ),
    ("black", "black", ["--check", "--diff", "plc_discovery", "tests", "simulators", "scripts", *TOP_LEVEL]),
    ("isort", "isort", ["--check-only", "--diff", "plc_discovery", "tests", "simulators", "scripts", *TOP_LEVEL]),
    (
        "mypy",
        "mypy",
        ["plc_discovery", "simulators", "scripts", *TOP_LEVEL, "--ignore-missing-imports", "--no-error-summary"],
    ),
]

# The CI's unit-test and integration-test jobs ("-q" for a shorter output;
# the coverage report itself is left out, its minimum is still checked)
UNIT_TESTS = [
    "tests/",
    "-q",
    "-m",
    "not integration",
    "--cov=plc_discovery",
    "--cov-report=",
    "--cov-fail-under=85",
]
INTEGRATION_TESTS = ["tests/integration/", "-q", "-m", "integration", "--tb=short"]

# Lines of a failed step's output shown in the summary
FAILURE_LINES = 40


class Result(NamedTuple):
    name: str
    passed: bool
    seconds: float
    detail: str


def pinned_versions(requirements: Path = ROOT / "requirements-dev.txt") -> Dict[str, str]:
    """name -> version of the tools pinned with '==' (black formats differently in another version)"""
    pins = {}
    for line in requirements.read_text(encoding="utf-8").splitlines():
        match = re.match(r"\s*([A-Za-z0-9_.-]+)==([^\s;#]+)", line)
        if match:
            pins[match.group(1).lower()] = match.group(2)
    return pins


def installed_version(name: str) -> Optional[str]:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def check_tools() -> Result:
    """The pinned lint tools in their pinned versions, and the pytest plugins the CI uses"""
    started = time.monotonic()
    problems = []
    for name, wanted in sorted(pinned_versions().items()):
        found = installed_version(name)
        if found is None:
            problems.append(f"{name} {wanted} is not installed")
        elif found != wanted:
            problems.append(f"{name} {found} is installed, the CI uses {wanted}")
    for plugin in ("pytest", "pytest-asyncio", "pytest-cov", "pytest-timeout"):
        if installed_version(plugin) is None:
            problems.append(f"{plugin} is not installed")
    if problems:
        detail = "\n".join(problems) + f"\nInstall them with: {sys.executable} -m pip install -r requirements-dev.txt"
        return Result("tools", False, time.monotonic() - started, detail)
    return Result("tools", True, time.monotonic() - started, "")


def run_step(name: str, args: List[str]) -> Result:
    """Run ``python -m <args>`` in the repository; its output is kept for the summary"""
    print(f"--- {name}: {' '.join(args)}", flush=True)
    started = time.monotonic()
    completed = subprocess.run(
        [sys.executable, "-m", *args],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    seconds = time.monotonic() - started
    output = completed.stdout.rstrip()
    lines = output.splitlines()
    if completed.returncode == 0:
        print(f"    ok ({seconds:.1f}s)" + (f": {lines[-1].strip()}" if lines else ""), flush=True)
        return Result(name, True, seconds, lines[-1].strip() if lines else "")
    print(f"    FAILED ({seconds:.1f}s, exit code {completed.returncode})", flush=True)
    return Result(name, False, seconds, "\n".join(lines[-FAILURE_LINES:]))


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run the CI checks locally and summarise them")
    parser.add_argument("--lint", action="store_true", help="Tools and lint only (no tests)")
    parser.add_argument("--no-integration", action="store_true", help="Skip the integration tests")
    args = parser.parse_args(argv)

    print(f"Python {sys.version.split()[0]} ({sys.executable})", flush=True)
    results = [check_tools()]
    print(f"--- tools: {'ok' if results[0].passed else 'FAILED'}", flush=True)
    for name, module, step_args in LINT_STEPS:
        results.append(run_step(name, [module, *step_args]))
    if not args.lint:
        results.append(run_step("unit tests", ["pytest", *UNIT_TESTS]))
        if not args.no_integration:
            results.append(run_step("integration tests", ["pytest", *INTEGRATION_TESTS]))

    print("\n=== Summary")
    for result in results:
        print(f"  {'ok    ' if result.passed else 'FAILED'}  {result.name:<18} {result.seconds:6.1f}s")
    failed = [result for result in results if not result.passed]
    for result in failed:
        print(f"\n=== {result.name} (FAILED)\n{result.detail}")
    if failed:
        print(f"\n{len(failed)} of {len(results)} checks FAILED: {', '.join(r.name for r in failed)}")
        return 1
    print(f"\nAll {len(results)} checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
