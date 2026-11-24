#!/usr/bin/env python3
"""
PLC simulator GUI: start / stop each protocol simulator, change the values
the scanner reads (by hand or automatically) and watch the log.

Usage:
    python simulators/simulator_gui.py [--host 127.0.0.1] [--start-all] [--state FILE]

Only the standard library (with Tkinter) is needed, like the simulators.
"""

import argparse
import logging
import os
import queue
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
from typing import Dict, List, Optional

if __package__ in (None, ""):
    # Direct execution (python simulators/simulator_gui.py)
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from control import (
        KINDS,
        KINDS_BY_KEY,
        WAVEFORM_LABELS,
        WAVEFORMS,
        Generator,
        SavedState,
        SimulatorController,
        SimulatorKind,
        SimulatorSetting,
        apply_state,
        scanner_command,
    )
else:
    from .control import (
        KINDS,
        KINDS_BY_KEY,
        WAVEFORM_LABELS,
        WAVEFORMS,
        Generator,
        SavedState,
        SimulatorController,
        SimulatorKind,
        SimulatorSetting,
        apply_state,
        scanner_command,
    )

APP_TITLE = "PLC シミュレータ"
HOSTS = ("127.0.0.1", "0.0.0.0")
LOG_LINES = 2000
STATE_FILES = [("シミュレータの状態", "*.json"), ("すべてのファイル", "*")]


def clients_text(clients: List[str]) -> str:
    """'3: 192.168.1.14, 127.0.0.1 ×2' for the connection column (ports change every connection: left out)"""
    if not clients:
        return "0"
    counts: Dict[str, int] = {}
    for client in clients:
        host = client.rsplit(":", 1)[0]
        counts[host] = counts.get(host, 0) + 1
    shown = [f"{host} ×{n}" if n > 1 else host for host, n in sorted(counts.items())]
    more = "、ほか" if len(shown) > 2 else ""
    return f"{len(clients)}: {', '.join(shown[:2])}{more}"


class QueueLogHandler(logging.Handler):
    """Hands log lines to the Tk thread"""

    def __init__(self, lines: "queue.Queue[str]"):
        super().__init__(logging.INFO)
        self.lines = lines
        self.setFormatter(logging.Formatter("%(asctime)s %(name)s: %(message)s", "%H:%M:%S"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.lines.put_nowait(self.format(record))
        except Exception:
            self.handleError(record)


class _Row:
    """One simulator's line: port, denied ranges, writes, state, connections and start/stop"""

    def __init__(self, app: "SimulatorApp", parent: tk.Misc, row: int, kind: SimulatorKind):
        self.kind = kind
        self.var_port = tk.StringVar(value=str(kind.port))
        self.var_denied = tk.StringVar(value=kind.denied or "（固定）")
        self.var_state = tk.StringVar(value="停止中")
        self.var_writable = tk.BooleanVar(value=False)
        self.var_clients = tk.StringVar(value="-")
        ttk.Label(parent, text=kind.title).grid(row=row, column=0, sticky=tk.W, padx=4, pady=2)
        self.ent_port = ttk.Entry(parent, textvariable=self.var_port, width=7)
        self.ent_port.grid(row=row, column=1, padx=4)
        self.ent_denied = ttk.Entry(parent, textvariable=self.var_denied, width=22)
        self.ent_denied.grid(row=row, column=2, padx=4, sticky=tk.EW)
        self.chk_writable = ttk.Checkbutton(parent, variable=self.var_writable)
        self.chk_writable.grid(row=row, column=3, padx=4)
        self.lbl_state = ttk.Label(parent, textvariable=self.var_state, width=14)
        self.lbl_state.grid(row=row, column=4, padx=4, sticky=tk.W)
        ttk.Label(parent, textvariable=self.var_clients, width=30).grid(row=row, column=5, padx=4, sticky=tk.W)
        self.btn = ttk.Button(parent, text="起動", width=6, command=lambda: app.toggle(kind.key))
        self.btn.grid(row=row, column=6, padx=4)
        ttk.Button(parent, text="コマンド", width=8, command=lambda: app.show_command(kind.key)).grid(
            row=row, column=7, padx=4
        )

    def update(self, running: bool, port: Optional[int]) -> None:
        state = tk.DISABLED if running else tk.NORMAL
        self.ent_port.configure(state=state)
        self.ent_denied.configure(state=tk.DISABLED if running or self.kind.denied is None else tk.NORMAL)
        self.chk_writable.configure(state=tk.DISABLED if running or not self.kind.writable else tk.NORMAL)
        self.var_state.set(f"実行中（{port}）" if running else "停止中")
        if not running:
            self.var_clients.set("-")
        self.btn.configure(text="停止" if running else "起動")


class SimulatorApp:
    def __init__(self, root: tk.Tk, host: str = "127.0.0.1"):
        self.root = root
        self.controller = SimulatorController()
        self.log_lines: "queue.Queue[str]" = queue.Queue()
        self._log_handler = QueueLogHandler(self.log_lines)
        logging.getLogger().addHandler(self._log_handler)
        if logging.getLogger().level > logging.INFO or logging.getLogger().level == logging.NOTSET:
            logging.getLogger().setLevel(logging.INFO)

        root.title(APP_TITLE)
        root.minsize(760, 620)
        self.var_host = tk.StringVar(value=host)
        self.var_command = tk.StringVar()
        self.var_sim = tk.StringVar()
        self.var_area = tk.StringVar()
        self.var_address = tk.StringVar(value="0")
        self.var_value = tk.StringVar()
        self.var_current = tk.StringVar(value="現在値: -")
        self.var_wave = tk.StringVar(value=WAVEFORM_LABELS["sine"])
        self.var_low = tk.StringVar(value="0")
        self.var_high = tk.StringVar(value="100")
        self.var_period = tk.StringVar(value="30")
        self.rows: Dict[str, _Row] = {}
        self._build()
        self._refresh_rows()
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.after(200, self._poll)

    # -- layout --

    def _build(self) -> None:
        main = ttk.Frame(self.root, padding=8)
        main.pack(fill=tk.BOTH, expand=True)

        top = ttk.Frame(main)
        top.pack(fill=tk.X)
        ttk.Label(top, text="待ち受けアドレス:").pack(side=tk.LEFT)
        self.cmb_host = ttk.Combobox(top, textvariable=self.var_host, values=HOSTS, width=14)
        self.cmb_host.pack(side=tk.LEFT, padx=4)
        ttk.Label(top, text="（0.0.0.0 は他のPCからも接続可。工場のネットワークでは使わないでください）").pack(
            side=tk.LEFT
        )
        ttk.Button(top, text="すべて停止", command=self.stop_all).pack(side=tk.RIGHT, padx=2)
        ttk.Button(top, text="すべて起動", command=self.start_all).pack(side=tk.RIGHT, padx=2)
        ttk.Button(top, text="状態を読み込む…", command=self.load_state).pack(side=tk.RIGHT, padx=2)
        ttk.Button(top, text="状態を保存…", command=self.save_state).pack(side=tk.RIGHT, padx=2)

        sims = ttk.LabelFrame(main, text="シミュレータ", padding=6)
        sims.pack(fill=tk.X, pady=6)
        for col, text in enumerate(("種類", "ポート", "読めないアドレス", "書き込み可", "状態", "接続中のクライアント")):
            ttk.Label(sims, text=text).grid(row=0, column=col, sticky=tk.W, padx=4)
        sims.columnconfigure(2, weight=1)
        for i, kind in enumerate(KINDS, start=1):
            self.rows[kind.key] = _Row(self, sims, i, kind)
        cmd = ttk.Frame(sims)
        cmd.grid(row=len(KINDS) + 1, column=0, columnspan=8, sticky=tk.EW, pady=(6, 0))
        ttk.Label(cmd, text="スキャナーのコマンド:").pack(side=tk.LEFT)
        ttk.Entry(cmd, textvariable=self.var_command, state="readonly").pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=4
        )
        ttk.Button(cmd, text="コピー", command=self.copy_command).pack(side=tk.LEFT)

        values = ttk.LabelFrame(main, text="値の確認・書き換え（実行中のシミュレータ）", padding=6)
        values.pack(fill=tk.X)
        line = ttk.Frame(values)
        line.pack(fill=tk.X)
        ttk.Label(line, text="シミュレータ:").pack(side=tk.LEFT)
        self.cmb_sim = ttk.Combobox(line, textvariable=self.var_sim, state="readonly", width=30)
        self.cmb_sim.pack(side=tk.LEFT, padx=4)
        self.cmb_sim.bind("<<ComboboxSelected>>", lambda e: self._on_sim_selected())
        ttk.Label(line, text="エリア:").pack(side=tk.LEFT)
        self.cmb_area = ttk.Combobox(line, textvariable=self.var_area, state="readonly", width=6)
        self.cmb_area.pack(side=tk.LEFT, padx=4)
        self.cmb_area.bind("<<ComboboxSelected>>", lambda e: self._on_area_selected())
        ttk.Label(line, text="アドレス／タグ:").pack(side=tk.LEFT)
        self.cmb_address = ttk.Combobox(line, textvariable=self.var_address, width=12)
        self.cmb_address.pack(side=tk.LEFT, padx=4)
        ttk.Label(line, textvariable=self.var_current, width=18).pack(side=tk.LEFT, padx=4)

        line = ttk.Frame(values)
        line.pack(fill=tk.X, pady=(4, 0))
        ttk.Label(line, text="値:").pack(side=tk.LEFT)
        ent_value = ttk.Entry(line, textvariable=self.var_value, width=12)
        ent_value.pack(side=tk.LEFT, padx=4)
        ent_value.bind("<Return>", lambda e: self.write_value())
        ttk.Button(line, text="書き込む", command=self.write_value).pack(side=tk.LEFT, padx=2)
        ttk.Label(line, text="（ビットは 0 / 1、ワードは -32768〜65535）").pack(side=tk.LEFT, padx=4)

        line = ttk.Frame(values)
        line.pack(fill=tk.X, pady=(4, 0))
        ttk.Label(line, text="自動変化:").pack(side=tk.LEFT)
        ttk.Combobox(
            line,
            textvariable=self.var_wave,
            values=[WAVEFORM_LABELS[w] for w in WAVEFORMS],
            state="readonly",
            width=10,
        ).pack(side=tk.LEFT, padx=4)
        for label, var in (("最小", self.var_low), ("最大", self.var_high), ("周期（秒）", self.var_period)):
            ttk.Label(line, text=label).pack(side=tk.LEFT)
            ttk.Entry(line, textvariable=var, width=7).pack(side=tk.LEFT, padx=(2, 6))
        ttk.Button(line, text="開始", command=self.start_generator).pack(side=tk.LEFT, padx=2)

        gens = ttk.Frame(values)
        gens.pack(fill=tk.X, pady=(4, 0))
        self.lst_generators = tk.Listbox(gens, height=3)
        self.lst_generators.pack(side=tk.LEFT, fill=tk.X, expand=True)
        buttons = ttk.Frame(gens)
        buttons.pack(side=tk.LEFT, padx=4)
        ttk.Button(buttons, text="選択を停止", command=self.stop_selected_generator).pack(fill=tk.X)
        ttk.Button(buttons, text="すべて停止", command=self.stop_all_generators).pack(fill=tk.X, pady=2)

        logs = ttk.LabelFrame(main, text="ログ", padding=6)
        logs.pack(fill=tk.BOTH, expand=True, pady=(6, 0))
        self.txt_log = ScrolledText(logs, height=10, state=tk.DISABLED)
        self.txt_log.pack(fill=tk.BOTH, expand=True)

    # -- simulators --

    def _running_keys(self) -> List[str]:
        return [k.key for k in KINDS if self.controller.is_running(k.key)]

    def _refresh_rows(self) -> None:
        for key, row in self.rows.items():
            row.update(self.controller.is_running(key), self.controller.port_of(key))
        running = self._running_keys()
        self.cmb_host.configure(state=tk.DISABLED if running else tk.NORMAL)
        titles = [KINDS_BY_KEY[k].title for k in running]
        self.cmb_sim.configure(values=titles)
        if self.var_sim.get() not in titles:
            self.var_sim.set(titles[0] if titles else "")
            self._on_sim_selected()
        self._refresh_generators()

    def _start(self, key: str) -> bool:
        row = self.rows[key]
        try:
            port = int(row.var_port.get())
        except ValueError:
            messagebox.showwarning("入力エラー", f"{row.kind.title}: ポートには数値を入力してください。")
            return False
        denied = row.var_denied.get().strip() if row.kind.denied is not None else None
        writable = row.var_writable.get() and row.kind.writable
        try:
            self.controller.start(key, self.var_host.get().strip() or "127.0.0.1", port, denied, writable)
        except Exception as e:
            logging.getLogger("Simulator-GUI").error(f"{row.kind.title}: failed to start: {e}")
            messagebox.showerror(
                "起動できません",
                f"{row.kind.title} を起動できませんでした。\n"
                f"ポート {port} が他のプログラム（run_all.py など）で使われていないか確認してください。\n\n{e}",
            )
            return False
        self.show_command(key)
        return True

    def toggle(self, key: str) -> None:
        if self.controller.is_running(key):
            self.controller.stop(key)
        else:
            self._start(key)
        self._refresh_rows()

    def start_all(self) -> None:
        for kind in KINDS:
            if not self.controller.is_running(kind.key) and not self._start(kind.key):
                break
        self._refresh_rows()

    def stop_all(self) -> None:
        self.controller.stop_all()
        self._refresh_rows()

    # -- saved state --

    def current_state(self) -> SavedState:
        """What the window shows now: each simulator's settings, hand-written values, automatic changes"""
        state = SavedState(host=self.var_host.get().strip() or "127.0.0.1")
        for key, row in self.rows.items():
            settings = self.controller.settings(key)
            if settings is not None:
                _, port, denied, writable = settings
                state.simulators[key] = SimulatorSetting(port, denied, writable, running=True)
                continue
            try:
                port = int(row.var_port.get())
            except ValueError:
                port = row.kind.port
            denied = row.var_denied.get().strip() if row.kind.denied is not None else None
            state.simulators[key] = SimulatorSetting(port, denied, bool(row.var_writable.get()), running=False)
        state.values = self.controller.written_values()
        state.generators = self.controller.generators()
        return state

    def save_state(self) -> None:
        path = filedialog.asksaveasfilename(
            title="状態を保存", defaultextension=".json", filetypes=STATE_FILES, initialfile="simulator_state.json"
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.current_state().to_json())
        except OSError as e:
            messagebox.showerror("保存できません", str(e))
            return
        logging.getLogger("Simulator-GUI").info(f"state saved: {path}")

    def load_state(self, path: Optional[str] = None) -> None:
        path = path or filedialog.askopenfilename(title="状態を読み込む", filetypes=STATE_FILES)
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as f:
                state = SavedState.from_json(f.read())
        except (OSError, ValueError) as e:
            messagebox.showerror("読み込めません", f"{path}\n\n{e}")
            return
        self.var_host.set(state.host)
        for key, setting in state.simulators.items():
            row = self.rows[key]
            row.var_port.set(str(setting.port))
            if row.kind.denied is not None and setting.denied is not None:
                row.var_denied.set(setting.denied)
            row.var_writable.set(setting.writable)
        problems = apply_state(self.controller, state)
        self._refresh_rows()
        logging.getLogger("Simulator-GUI").info(f"state loaded: {path}")
        for problem in problems:
            logging.getLogger("Simulator-GUI").error(problem)
        if problems:
            messagebox.showwarning("一部を復元できませんでした", "\n".join(problems))

    def show_command(self, key: str) -> None:
        kind = KINDS_BY_KEY[key]
        port = self.controller.port_of(key)
        if port is None:
            try:
                port = int(self.rows[key].var_port.get())
            except ValueError:
                port = kind.port
        self.var_command.set(scanner_command(kind, self.var_host.get().strip(), port))

    def copy_command(self) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(self.var_command.get())

    # -- values --

    def _selected_key(self) -> Optional[str]:
        title = self.var_sim.get()
        return next((k.key for k in KINDS if k.title == title), None)

    def _on_sim_selected(self) -> None:
        key = self._selected_key()
        areas = list(KINDS_BY_KEY[key].areas) if key else []
        self.cmb_area.configure(values=areas)
        if self.var_area.get() not in areas:
            self.var_area.set(areas[0] if areas else "")
        self._on_area_selected()

    def _on_area_selected(self) -> None:
        key = self._selected_key()
        if key and self.var_area.get() == "TAG":
            tags = self.controller.tags(key) if self.controller.is_running(key) else []
            self.cmb_address.configure(values=tags)
            if self.var_address.get() not in tags:
                self.var_address.set(tags[0] if tags else "")
        else:
            self.cmb_address.configure(values=[])
            if not self.var_address.get().strip().isdigit():
                self.var_address.set("0")

    def _target(self):
        key = self._selected_key()
        if key is None:
            raise ValueError("先にシミュレータを起動してください。")
        area = self.var_area.get()
        text = self.var_address.get().strip()
        if area == "TAG":
            if not text:
                raise ValueError("タグを選んでください。")
            return key, area, text
        try:
            address = int(text)
        except ValueError:
            raise ValueError("アドレスには 0 以上の整数を入力してください。") from None
        if address < 0:
            raise ValueError("アドレスには 0 以上の整数を入力してください。")
        return key, area, address

    @staticmethod
    def _number(text: str, what: str) -> float:
        try:
            return float(text)
        except ValueError:
            raise ValueError(f"「{what}」には数値を入力してください。") from None

    def write_value(self) -> None:
        try:
            key, area, address = self._target()
            value = self._number(self.var_value.get(), "値")
            self.controller.write(key, area, address, value)
        except ValueError as e:
            messagebox.showwarning("入力エラー", str(e))
            return
        logging.getLogger("Simulator-GUI").info(f"{KINDS_BY_KEY[key].title}: {area} {address} = {value:g}")
        self._update_current()

    def start_generator(self) -> None:
        try:
            key, area, address = self._target()
            waveform = next(w for w, label in WAVEFORM_LABELS.items() if label == self.var_wave.get())
            generator = Generator(
                key,
                area,
                address,
                waveform,
                self._number(self.var_low.get(), "最小"),
                self._number(self.var_high.get(), "最大"),
                self._number(self.var_period.get(), "周期"),
            )
            self.controller.start_generator(generator)
        except ValueError as e:
            messagebox.showwarning("入力エラー", str(e))
            return
        logging.getLogger("Simulator-GUI").info(f"auto change started: {generator.label}")
        self._refresh_generators()

    def _refresh_generators(self) -> None:
        self.lst_generators.delete(0, tk.END)
        self._generators = self.controller.generators()
        for generator in self._generators:
            self.lst_generators.insert(tk.END, generator.label)

    def stop_selected_generator(self) -> None:
        for index in self.lst_generators.curselection():
            g = self._generators[index]
            self.controller.stop_generator(g.kind, g.area, g.address)
        self._refresh_generators()

    def stop_all_generators(self) -> None:
        self.controller.stop_all_generators()
        self._refresh_generators()

    def _update_current(self) -> None:
        try:
            key, area, address = self._target()
            value = self.controller.read(key, area, address)
        except Exception:
            self.var_current.set("現在値: -")
            return
        self.var_current.set(f"現在値: {value:g}")

    # -- log and housekeeping --

    def _poll(self) -> None:
        try:
            self._refresh()
        except Exception:
            # e.g. a controller call timing out: keep polling, or the window
            # would stop updating for good
            logging.getLogger(__name__).exception("Simulator window update failed")
        finally:
            self.root.after(500, self._poll)

    def _refresh(self) -> None:
        lines = []
        while True:
            try:
                lines.append(self.log_lines.get_nowait())
            except queue.Empty:
                break
        if lines:
            self.txt_log.configure(state=tk.NORMAL)
            self.txt_log.insert(tk.END, "\n".join(lines) + "\n")
            # Keep the pane bounded during long runs
            excess = int(self.txt_log.index("end-1c").split(".")[0]) - LOG_LINES
            if excess > 0:
                self.txt_log.delete("1.0", f"{excess + 1}.0")
            self.txt_log.see(tk.END)
            self.txt_log.configure(state=tk.DISABLED)
        self._update_current()
        for key, row in self.rows.items():
            if self.controller.is_running(key):
                row.var_clients.set(clients_text(self.controller.clients(key)))

    def close(self) -> None:
        try:
            self.controller.shutdown()
        finally:
            logging.getLogger().removeHandler(self._log_handler)
            self.root.destroy()


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="PLC simulator GUI")
    parser.add_argument("--host", default="127.0.0.1", help="Address to listen on (default 127.0.0.1)")
    parser.add_argument("--start-all", action="store_true", help="Start every simulator at once")
    parser.add_argument("--state", metavar="FILE", help="Apply a state saved from the window (JSON)")
    args = parser.parse_args(argv)
    root = tk.Tk()
    app = SimulatorApp(root, host=args.host)
    if args.state:
        root.after(100, lambda: app.load_state(args.state))
    elif args.start_all:
        root.after(100, app.start_all)
    root.mainloop()


if __name__ == "__main__":
    main()
