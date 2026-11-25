"""
scripts/check.py runs the CI's checks locally: its commands must stay the
ones in .github/workflows/ci.yml, or "all checks passed" here would still
end in a failed CI run.
"""

import importlib.util
import re
import shlex
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CI = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

spec = importlib.util.spec_from_file_location("check_script", ROOT / "scripts" / "check.py")
assert spec and spec.loader
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def _ci_command(tool: str):
    """The arguments of the CI's ``tool`` line, with $TOP_LEVEL expanded"""
    top_level = re.search(r"TOP_LEVEL:\s*(.+)", CI).group(1).split()
    (line,) = [ln.strip() for ln in CI.splitlines() if ln.strip().startswith(f"{tool} ")]
    args = []
    for word in shlex.split(line)[1:]:
        args += top_level if word == "$TOP_LEVEL" else [word]
    return args


def test_top_level_is_the_ci_one():
    assert check.TOP_LEVEL == re.search(r"TOP_LEVEL:\s*(.+)", CI).group(1).split()


@pytest.mark.parametrize("name, module, args", check.LINT_STEPS, ids=[s[0] for s in check.LINT_STEPS])
def test_lint_steps_are_the_ci_commands(name, module, args):
    assert args == _ci_command(module)


def test_lint_tool_pins_match_the_ci_install_line():
    pins = check.pinned_versions()
    (line,) = [ln for ln in CI.splitlines() if "pip install black==" in ln]
    for name, version in re.findall(r"([a-z0-9-]+)==([^\s]+)", line):
        assert pins.get(name) == version, f"{name}: requirements-dev.txt and ci.yml pin different versions"


def test_test_steps_select_what_the_ci_jobs_run():
    assert '-m "not integration"' in CI and "--cov-fail-under=60" in CI
    assert check.UNIT_TESTS[check.UNIT_TESTS.index("-m") + 1] == "not integration"
    assert "--cov-fail-under=60" in check.UNIT_TESTS
    assert "pytest tests/integration/ -v -m integration" in CI
    assert check.INTEGRATION_TESTS[check.INTEGRATION_TESTS.index("-m") + 1] == "integration"


def test_every_step_runs_and_the_summary_names_the_failure(monkeypatch, capsys):
    """A failing lint step must not stop the later ones, nor hide behind them"""
    ran = []

    def fake_step(name, args):
        ran.append(name)
        return check.Result(name, name != "black", 0.1, "would reformat x.py" if name == "black" else "")

    monkeypatch.setattr(check, "run_step", fake_step)
    monkeypatch.setattr(check, "check_tools", lambda: check.Result("tools", True, 0.0, ""))
    assert check.main(["--no-integration"]) == 1
    assert ran == ["flake8", "black", "isort", "mypy", "unit tests"]
    out = capsys.readouterr().out
    assert "FAILED  black" in out and "would reformat x.py" in out
    assert "1 of 6 checks FAILED: black" in out


def test_missing_or_other_tool_versions_are_reported(monkeypatch):
    versions = {"black": "24.1.0", "pytest-timeout": None}
    monkeypatch.setattr(
        check,
        "installed_version",
        lambda name: versions[name] if name in versions else check.pinned_versions().get(name, "1.0"),
    )
    result = check.check_tools()
    assert not result.passed
    assert "black 24.1.0 is installed, the CI uses 26.5.1" in result.detail
    assert "pytest-timeout is not installed" in result.detail
