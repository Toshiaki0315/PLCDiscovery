"""
Regression tests for the findings of the seventh code review.

- GUI: "~" in the output folder and the settings file was not expanded
  where the folder is opened and the settings are saved / loaded: a folder
  named "~" was created where the GUI was started
- CLI: a mistyped --range / --target / --discover-protocols was reported to
  the notification destinations as a scan error
"""

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

import plc_gui
import plc_gui_settings
import plc_scanner
from plc_discovery.output import DEFAULT_OUTPUT_DIR


class _Var:
    def __init__(self, value):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


# ----------------------------------------------------------------------
# GUI: "~" in paths
# ----------------------------------------------------------------------


@pytest.fixture
def home(tmp_path, monkeypatch):
    """A home folder and a separate folder the GUI was started in"""
    home = tmp_path / "home"
    start = tmp_path / "start"
    home.mkdir()
    start.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.chdir(start)
    return home


def _opened_folder(monkeypatch, text):
    opened = []
    monkeypatch.setattr(plc_gui.sys, "platform", "darwin")
    monkeypatch.setattr(plc_gui.subprocess, "Popen", lambda command: opened.append(command[-1]))
    app = MagicMock()
    app.var_output_dir = _Var(text)
    plc_gui.PLCScannerApp._open_output_dir(app)
    return Path(opened[0])


def test_gui_opens_the_output_folder_in_the_home_folder(home, monkeypatch):
    opened = _opened_folder(monkeypatch, "~/plc_results")
    assert opened == home / "plc_results" and opened.is_dir()
    assert not Path("~").exists()  # was created where the GUI was started, and opened empty


@pytest.mark.parametrize("text", ["", "   "])
def test_gui_opens_the_default_output_folder_for_an_empty_field(home, monkeypatch, text):
    opened = _opened_folder(monkeypatch, text)
    assert opened.resolve() == Path(DEFAULT_OUTPUT_DIR).resolve()  # was the folder the GUI was started in


def _settings_app(path_text):
    class App(plc_gui_settings.SettingsTabsMixin):
        var_settings_path = _Var(path_text)
        var_status = _Var("")
        worker = None

        def _settings_dict(self):
            return {"network": {"packet_interval_ms": 70}}

        def _apply_settings(self, config):
            self.applied = config

        def _start_audit_log(self, config):
            pass

    return App()


def test_gui_saves_and_loads_the_settings_file_in_the_home_folder(home, monkeypatch):
    monkeypatch.setattr(plc_gui_settings.messagebox, "showinfo", MagicMock())
    monkeypatch.setattr(plc_gui_settings.messagebox, "showerror", MagicMock())
    app = _settings_app("~/plc_config.json")
    app._save_settings()
    saved = home / "plc_config.json"
    assert json.loads(saved.read_text(encoding="utf-8"))["network"]["packet_interval_ms"] == 70
    assert not Path("~").exists()  # was ./~/plc_config.json

    app._load_settings()
    assert app.applied["network"]["packet_interval_ms"] == 70  # was "設定ファイルがありません"
    plc_gui_settings.messagebox.showinfo.assert_not_called()


# ----------------------------------------------------------------------
# CLI: mistyped arguments are not scan errors
# ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "arguments, message",
    [
        (["--mode", "range", "--target", "127.0.0.1", "--protocol", "slmp", "--range", "5-"], "Invalid address range"),
        (["--mode", "range", "--target", "127.0.0.1", "--protocol", "slmp", "--range", "9-3"], "start must be <= end"),
        (["--mode", "full", "--target", "127.0.0.1,bad host", "--protocol", "slmp"], "Invalid --target"),
        (["--mode", "discover", "--ip-range", "127.0.0.1", "--discover-protocols", "slmp,foo"], "Unknown protocol"),
    ],
)
def test_mistyped_arguments_end_the_run_before_anything_is_opened(tmp_path, monkeypatch, capsys, arguments, message):
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps({"notifications": [{"name": "n", "type": "webhook", "url": "http://127.0.0.1:9/hook"}]}),
        encoding="utf-8",
    )
    audit = tmp_path / "audit.jsonl"
    database = tmp_path / "data.db"
    notify = AsyncMock(return_value=True)
    monkeypatch.setattr(plc_scanner, "_notify", notify)
    monkeypatch.setattr(
        "sys.argv",
        ["plc_scanner.py", "--no-rich", "-c", str(config), "-o", str(tmp_path / "out")]
        + ["--audit-log", str(audit), "--database", str(database)]
        + arguments,
    )
    with pytest.raises(SystemExit) as exit_info:
        asyncio.run(plc_scanner.run_cli())
    assert exit_info.value.code == 1
    assert message in capsys.readouterr().out
    notify.assert_not_called()  # was a "PLC Scan Error" at priority HIGH
    # ... and no audit session or database is left behind for a run that never started
    assert not audit.exists() and not database.exists() and not (tmp_path / "out").exists()
