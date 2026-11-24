#!/usr/bin/env python3
"""
PLC Scanner GUI - PLC自動探索・データ収集ツールのグラフィカル画面

標準ライブラリの Tkinter のみで動作します（追加インストール不要）。
通信処理はバックグラウンドスレッドの asyncio ループで実行するため、
スキャン中も画面が固まりません。

起動方法:
    python plc_gui.py

安全設計:
    - 読み取り専用（書き込み機能はありません）
    - パケット間隔・タイムアウトは「通信設定」タブで調整
    - フルスキャン開始時は工場停止中であることを確認するダイアログを表示
"""

import asyncio
import logging
import math
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable, Coroutine, Dict, List, Optional, Sequence

from plc_discovery import settings_file
from plc_discovery.audit_log import get_audit_logger
from plc_discovery.broadcast_discovery import BroadcastDiscovery
from plc_discovery.cli_args import parse_tag_list
from plc_discovery.collector import PLCDataCollector, unreached_points
from plc_discovery.config import (
    MAX_RANGE_POINTS,
    PROTOCOL_PORTS,
    DataPoint,
    DeviceRange,
    DeviceType,
    NetworkConfig,
    PLCInfo,
    Protocol,
    StatusCode,
    TagRange,
)
from plc_discovery.data_types import ByteOrder, DataType
from plc_discovery.discovery import PLCDiscovery, discover_plcs, merge_discovery_results
from plc_discovery.output import DEFAULT_OUTPUT_DIR, CSVExporter
from plc_discovery.scan_runner import CycleRunner, ResultWriter, ScanItem, next_cycle_wait, plc_answered
from plc_discovery.thresholds import Threshold, ThresholdMonitor, parse_thresholds
from plc_discovery.utils import (
    MAX_IP_RANGE_HOSTS,
    ip_range_error,
    melsec_address,
    success_rate_text,
    target_address_error,
)
from plc_gui_settings import JobOutputs, SettingsTabsMixin  # noqa: F401  (JobOutputs re-exported)
from plc_gui_tags import TagPickerDialog, fetch_tag_list
from plc_scanner import BYTE_ORDER_MAP, DATA_TYPE_MAP

APP_TITLE = "PLC Discovery - PLC自動探索・データ収集ツール"

# Treeview に表示する最大行数（全件は CSV に保存される）
MAX_DISPLAY_ROWS = 5000

# 周期実行の最小間隔（秒）: 生産中のPLCに負荷をかけないための下限
MIN_PERIODIC_INTERVAL_SEC = 1.0

PROTOCOL_CHOICES = ["自動検出"] + [p.name for p in Protocol]

STATUS_LABELS = {
    StatusCode.OK: "OK",
    StatusCode.NG_ILLEGAL_ADDR: "NG: 無効アドレス",
    StatusCode.NG_TIMEOUT: "NG: タイムアウト",
    StatusCode.NG_COMM_ERROR: "NG: 通信エラー",
    StatusCode.NG_UNSUPPORTED: "NG: 非対応",
}

BYTE_ORDER_LABELS = {
    "little": "リトル CDAB（下位ワード先頭・標準）",
    "big": "ビッグ ABCD（上位ワード先頭）",
    "little_swap": "リトル + バイトスワップ DCBA",
    "big_swap": "ビッグ + バイトスワップ BADC",
}


# ---------------------------------------------------------------------------
# バックグラウンド処理（通信用ワーカー）
# ---------------------------------------------------------------------------


class AsyncWorker:
    """専用スレッドで asyncio ループを回し、GUI スレッドからジョブを投入する"""

    def __init__(self, acknowledge: bool = False) -> None:
        """
        Args:
            acknowledge: stay busy after a job has ended until the caller
                confirms with acknowledge() that it has handled the result.
                The GUI learns about the end through a queue it polls: a
                job submitted in between would be running while the old
                result re-enables Start and disables Stop.
        """
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, daemon=True, name="plc-worker")
        self._thread.start()
        self._task: Optional["asyncio.Task[Any]"] = None
        # True from submit() until the job - including its cleanup after a
        # cancel (final notification, PLC disconnect) - has really ended
        self._running = False
        self._acknowledge = acknowledge
        # The job has ended and its result is not handled yet
        self._unacknowledged = False

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    @property
    def busy(self) -> bool:
        return self._running or self._unacknowledged

    def acknowledge(self) -> None:
        """The result of the job that ended has been handled: a new job may start"""
        self._unacknowledged = False

    def submit(self, coro: Coroutine[Any, Any, Any], on_done: Callable[[Optional[BaseException]], None]) -> None:
        """コルーチンを投入する。完了時に on_done(例外 or None) をワーカースレッドで呼ぶ"""
        self._running = True

        def _done(task: "asyncio.Task[Any]") -> None:
            # Runs when the task is over, i.e. after its except/finally
            # blocks. (A concurrent Future's cancel() reported "done" at
            # once: Start was enabled again while the stopped job was still
            # disconnecting, and a second job could reach the same PLC.)
            self._unacknowledged = self._acknowledge
            self._running = False
            on_done(asyncio.CancelledError() if task.cancelled() else task.exception())

        def _start() -> None:
            self._task = self.loop.create_task(coro)
            self._task.add_done_callback(_done)

        self.loop.call_soon_threadsafe(_start)

    def cancel(self) -> None:
        def _cancel() -> None:
            if self._task is not None and not self._task.done():
                self._task.cancel()

        self.loop.call_soon_threadsafe(_cancel)

    def shutdown(self, timeout: float = 3.0) -> None:
        """
        Cancel running jobs, wait (bounded) until their cleanup such as
        PLC disconnect has finished, then stop the loop. Stopping the loop
        right away would leave the PLC connection open.
        """

        async def _cancel_all() -> None:
            current = asyncio.current_task()
            tasks = [t for t in asyncio.all_tasks() if t is not current]
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        try:
            asyncio.run_coroutine_threadsafe(_cancel_all(), self.loop).result(timeout)
        except Exception as e:  # timeout etc.: stop anyway
            logging.getLogger(__name__).debug(f"Worker shutdown incomplete: {e}")
        self.loop.call_soon_threadsafe(self.loop.stop)


class QueueLogHandler(logging.Handler):
    """ログレコードを GUI キューへ流す"""

    def __init__(self, q: "queue.Queue") -> None:
        super().__init__()
        self.q = q
        self.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.q.put(("log", record.levelname, self.format(record)))
        except Exception:
            pass


# ---------------------------------------------------------------------------
# メイン画面
# ---------------------------------------------------------------------------


class PLCScannerApp(SettingsTabsMixin):
    """PLC探索・データ収集ツールのメイン画面"""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(APP_TITLE)
        # Fits the collect tab (tag field) and the discovery table; capped to
        # the screen so small laptop displays still show the whole window
        width = min(1160, self.root.winfo_screenwidth() - 40)
        height = min(860, self.root.winfo_screenheight() - 80)
        self.root.geometry(f"{width}x{height}")
        self.root.minsize(900, 620)

        self.ui_queue: "queue.Queue" = queue.Queue()
        self.worker = AsyncWorker(acknowledge=True)
        self.discovered: List[PLCInfo] = []
        self.last_output_dir: Optional[Path] = None

        logging.getLogger().addHandler(QueueLogHandler(self.ui_queue))
        logging.getLogger().setLevel(logging.INFO)
        # Libraries' own expected-failure logs (with tracebacks) are not shown
        # in the log pane; the tool reports the outcome itself
        for name in ("pycomm3", "pymodbus"):
            logging.getLogger(name).setLevel(logging.CRITICAL)

        self._init_vars()
        self._build_style()
        self._build_layout()
        self._on_mode_change()
        self._on_discover_scope_change()
        # Settings saved earlier (③〜⑤ tabs): loaded if the file exists
        self._load_settings(quiet=True)

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(100, self._poll_queue)

    # ----- 画面の状態（入力値など） ----------------------------------

    def _init_vars(self) -> None:
        # PLC探索タブ
        self.var_scope = tk.StringVar(value="segment")
        self.var_ip_range = tk.StringVar(value="192.168.1.0/24")
        self.var_broadcast = tk.BooleanVar(value=True)

        # データ収集タブ
        self.var_target = tk.StringVar()
        self.var_protocol = tk.StringVar(value=PROTOCOL_CHOICES[0])
        self.var_port = tk.StringVar()
        self.var_mode = tk.StringVar(value="range")
        self.var_device = tk.StringVar(value=DeviceType.D.value)
        self.var_start = tk.StringVar(value="0")
        self.var_end = tk.StringVar(value="99")
        self.var_tags = tk.StringVar()
        self.var_periodic = tk.BooleanVar(value=False)
        self.var_interval = tk.StringVar(value="60")
        self.var_thresholds = tk.StringVar()
        self.var_data_type = tk.StringVar(value="(変換なし)")
        self.var_byte_order = tk.StringVar(value=BYTE_ORDER_LABELS["little"])
        self.var_ng_only = tk.BooleanVar(value=False)

        # 通信・出力設定タブ
        self.var_packet_interval = tk.StringVar(value="50")
        self.var_retry_interval = tk.StringVar(value="200")
        self.var_timeout = tk.StringVar(value="5000")
        self.var_output_dir = tk.StringVar(value=str(Path(DEFAULT_OUTPUT_DIR).resolve()))
        self.var_encoding = tk.StringVar(value="utf-8-sig")
        self.var_hex_addresses = tk.BooleanVar(value=False)
        self.var_periodic_csv = tk.StringVar(value="per_cycle")
        self._last_protocol: Optional[Protocol] = None
        self.var_settings_path = tk.StringVar(value=str(Path(settings_file.DEFAULT_SETTINGS_FILE).resolve()))

        # 通知タブ（通知先は設定ファイルの notifications[] と同じ形の dict）
        self.notify_destinations: List[Dict] = []
        self.var_report_interval = tk.StringVar(value="0")
        self.var_min_interval = tk.StringVar(value="0")

        # データベースタブ
        self.var_db_enabled = tk.BooleanVar(value=False)
        self.var_db_path = tk.StringVar(value=str(Path("plc_data.db").resolve()))
        self.var_db_history = tk.BooleanVar(value=True)
        self.var_db_days = tk.StringVar(value="30")
        self.var_db_size = tk.StringVar(value="0")
        self.var_db_interval = tk.StringVar(value="24")
        self.var_db_status = tk.StringVar(value="")

        # ステータス表示
        self.var_status = tk.StringVar(value="準備完了")
        self.var_summary = tk.StringVar(value="")

        self._last_points: List[DataPoint] = []

    # ----- 画面レイアウト ---------------------------------------

    def _build_style(self) -> None:
        style = ttk.Style(self.root)
        if sys.platform.startswith("win") and "vista" in style.theme_names():
            style.theme_use("vista")
        elif "clam" in style.theme_names() and sys.platform != "darwin":
            style.theme_use("clam")
        style.configure("Title.TLabel", font=("", 13, "bold"))
        style.configure("Hint.TLabel", foreground="#666666")
        style.configure("Primary.TButton", font=("", 11, "bold"), padding=(14, 6))
        style.configure("Treeview", rowheight=22)

    def _build_layout(self) -> None:
        outer = ttk.Frame(self.root, padding=10)
        outer.pack(fill=tk.BOTH, expand=True)

        paned = ttk.PanedWindow(outer, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True)

        self.notebook = ttk.Notebook(paned)
        paned.add(self.notebook, weight=4)

        self.tab_discover = ttk.Frame(self.notebook, padding=10)
        self.tab_collect = ttk.Frame(self.notebook, padding=10)
        self.tab_settings = ttk.Frame(self.notebook, padding=10)
        self.tab_notify = ttk.Frame(self.notebook, padding=10)
        self.tab_db = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_discover, text="  ① PLC探索  ")
        self.notebook.add(self.tab_collect, text="  ② データ収集  ")
        self.notebook.add(self.tab_settings, text="  ③ 通信・出力設定  ")
        self.notebook.add(self.tab_notify, text="  ④ 通知  ")
        self.notebook.add(self.tab_db, text="  ⑤ データベース  ")

        self._build_discover_tab()
        self._build_collect_tab()
        self._build_settings_tab()
        self._build_notify_tab()
        self._build_db_tab()

        # ログ表示エリア
        log_frame = ttk.LabelFrame(paned, text="ログ", padding=6)
        paned.add(log_frame, weight=1)
        self.log_text = tk.Text(
            log_frame,
            height=7,
            wrap=tk.NONE,
            state=tk.DISABLED,
            font=("Menlo", 10) if sys.platform == "darwin" else ("Consolas", 9),
        )
        log_scroll = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.tag_configure("WARNING", foreground="#b26a00")
        self.log_text.tag_configure("ERROR", foreground="#c62828")

        # ステータスバー（進捗バー・停止ボタン）
        status = ttk.Frame(outer, padding=(0, 6, 0, 0))
        status.pack(fill=tk.X)
        self.progress = ttk.Progressbar(status, mode="determinate", length=260)
        self.progress.pack(side=tk.LEFT)
        ttk.Label(status, textvariable=self.var_status).pack(side=tk.LEFT, padx=10)
        self.btn_stop = ttk.Button(status, text="■ 停止", command=self._stop, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.RIGHT)
        ttk.Button(status, text="出力フォルダを開く", command=self._open_output_dir).pack(side=tk.RIGHT, padx=6)

    def _build_discover_tab(self) -> None:
        f = self.tab_discover
        ttk.Label(f, text="ネットワーク上のPLCを探します", style="Title.TLabel").pack(anchor=tk.W)
        ttk.Label(
            f,
            text="SLMP / EtherNet/IP / Modbus/TCP / S7 / FINS のポートに問い合わせ、応答したPLCを一覧表示します。",
            style="Hint.TLabel",
        ).pack(anchor=tk.W, pady=(0, 8))

        opts = ttk.LabelFrame(f, text="探索範囲", padding=8)
        opts.pack(fill=tk.X)
        ttk.Radiobutton(
            opts,
            text="同じネットワーク（自動）",
            value="segment",
            variable=self.var_scope,
            command=self._on_discover_scope_change,
        ).grid(row=0, column=0, sticky=tk.W)
        ttk.Radiobutton(
            opts, text="IP範囲を指定:", value="range", variable=self.var_scope, command=self._on_discover_scope_change
        ).grid(row=0, column=1, sticky=tk.W, padx=(20, 4))
        self.ent_ip_range = ttk.Entry(opts, textvariable=self.var_ip_range, width=26)
        self.ent_ip_range.grid(row=0, column=2, sticky=tk.W)
        ttk.Label(opts, text="例: 192.168.1.0/24  または  192.168.1.10-192.168.1.50", style="Hint.TLabel").grid(
            row=1, column=2, sticky=tk.W
        )
        ttk.Label(opts, text="このPCで動かしているPLCシミュレータを探す場合: 127.0.0.1", style="Hint.TLabel").grid(
            row=2, column=2, sticky=tk.W
        )
        ttk.Checkbutton(opts, text="UDPブロードキャスト探索も行う", variable=self.var_broadcast).grid(
            row=1, column=0, sticky=tk.W, pady=(4, 0)
        )

        btns = ttk.Frame(f)
        btns.pack(fill=tk.X, pady=8)
        self.btn_discover = ttk.Button(btns, text="▶ 探索開始", style="Primary.TButton", command=self._start_discovery)
        self.btn_discover.pack(side=tk.LEFT)
        self.btn_to_collect = ttk.Button(
            btns, text="選択したPLCのデータを収集 →", command=self._use_selected_plc, state=tk.DISABLED
        )
        self.btn_to_collect.pack(side=tk.LEFT, padx=10)
        self.lbl_discover_count = ttk.Label(btns, text="")
        self.lbl_discover_count.pack(side=tk.RIGHT)

        cols = ("ip", "manufacturer", "model", "cpu", "firmware", "protocol", "port", "read", "mac")
        headings = (
            "IPアドレス",
            "メーカー",
            "機種",
            "型式・CPU",
            "ファームウェア",
            "プロトコル",
            "ポート",
            "読み方",
            "MACアドレス",
        )
        widths = (100, 130, 170, 140, 80, 100, 50, 170, 110)
        self.tree_plc = self._make_tree(f, cols, headings, widths)
        self.tree_plc.bind(
            "<<TreeviewSelect>>",
            lambda e: self.btn_to_collect.configure(state=tk.NORMAL if self.tree_plc.selection() else tk.DISABLED),
        )
        self.tree_plc.bind("<Double-1>", lambda e: self._use_selected_plc())
        ttk.Label(
            f, text="ヒント: 行をダブルクリックすると、そのPLCを「データ収集」タブに設定します。", style="Hint.TLabel"
        ).pack(anchor=tk.W, pady=(4, 0))

    def _build_collect_tab(self) -> None:
        f = self.tab_collect
        top = ttk.Frame(f)
        top.pack(fill=tk.X)

        # 接続先PLC
        tgt = ttk.LabelFrame(top, text="接続先PLC", padding=8)
        tgt.pack(side=tk.LEFT, fill=tk.BOTH, padx=(0, 8))
        ttk.Label(tgt, text="IPアドレス").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(tgt, textvariable=self.var_target, width=18).grid(row=0, column=1, sticky=tk.W, pady=2)
        ttk.Label(tgt, text="プロトコル").grid(row=1, column=0, sticky=tk.W)
        cb_proto = ttk.Combobox(
            tgt, textvariable=self.var_protocol, values=PROTOCOL_CHOICES, state="readonly", width=16
        )
        cb_proto.grid(row=1, column=1, sticky=tk.W, pady=2)
        cb_proto.bind("<<ComboboxSelected>>", self._on_protocol_change)
        ttk.Label(tgt, text="ポート").grid(row=2, column=0, sticky=tk.W)
        ttk.Entry(tgt, textvariable=self.var_port, width=8).grid(row=2, column=1, sticky=tk.W, pady=2)
        ttk.Label(tgt, text="空欄=標準ポート", style="Hint.TLabel").grid(row=3, column=1, sticky=tk.W)

        # 収集モード
        mode = ttk.LabelFrame(top, text="収集モード", padding=8)
        mode.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))
        ttk.Radiobutton(
            mode, text="範囲指定（生産中でも可）", value="range", variable=self.var_mode, command=self._on_mode_change
        ).grid(row=0, column=0, columnspan=4, sticky=tk.W)
        ttk.Label(mode, text="デバイス").grid(row=1, column=0, sticky=tk.W, padx=(20, 4))
        self.cb_device = ttk.Combobox(
            mode, textvariable=self.var_device, values=[d.value for d in DeviceType], state="readonly", width=5
        )
        self.cb_device.grid(row=1, column=1, sticky=tk.W)
        ttk.Label(mode, text="アドレス").grid(row=1, column=2, sticky=tk.W, padx=(10, 4))
        rng = ttk.Frame(mode)
        rng.grid(row=1, column=3, sticky=tk.W)
        self.ent_start = ttk.Entry(rng, textvariable=self.var_start, width=7)
        self.ent_start.pack(side=tk.LEFT)
        ttk.Label(rng, text=" 〜 ").pack(side=tk.LEFT)
        self.ent_end = ttk.Entry(rng, textvariable=self.var_end, width=7)
        self.ent_end.pack(side=tk.LEFT)
        # GX Works shows X/Y/B/W in hexadecimal; this tool uses decimal
        # everywhere and converts when sending (README: 範囲指定モード).
        # Own row: next to the address fields it pushed the data type
        # frame out of the window
        ttk.Label(mode, text="アドレスは10進数で入力（X/Y/B/W も。例: X1F → 31）", style="Hint.TLabel").grid(
            row=2, column=0, columnspan=4, sticky=tk.W, padx=(20, 0)
        )

        # EtherNet/IP symbolic tags (Logix / Omron NJ/NX): read instead of
        # the device range when filled in
        tag_row = ttk.Frame(mode)
        tag_row.grid(row=3, column=0, columnspan=4, sticky=tk.W, padx=(20, 0), pady=(4, 0))
        ttk.Label(tag_row, text="タグ（EtherNet/IP）").pack(side=tk.LEFT)
        self.ent_tags = ttk.Entry(tag_row, textvariable=self.var_tags, width=24)
        self.ent_tags.pack(side=tk.LEFT, padx=(4, 0))
        self.btn_tag_list = ttk.Button(tag_row, text="一覧…", width=5, command=self._pick_tags)
        self.btn_tag_list.pack(side=tk.LEFT, padx=(4, 0))
        ttk.Label(mode, text="カンマ区切り。入力するとアドレスの代わりに読みます", style="Hint.TLabel").grid(
            row=4, column=0, columnspan=4, sticky=tk.W, padx=(20, 0)
        )

        per = ttk.Frame(mode)
        per.grid(row=5, column=0, columnspan=4, sticky=tk.W, padx=(20, 0), pady=(4, 0))
        self.chk_periodic = ttk.Checkbutton(
            per, text="周期実行:", variable=self.var_periodic, command=self._on_mode_change
        )
        self.chk_periodic.pack(side=tk.LEFT)
        self.ent_interval = ttk.Entry(per, textvariable=self.var_interval, width=6)
        self.ent_interval.pack(side=tk.LEFT)
        ttk.Label(per, text="秒ごと（停止ボタンで終了）").pack(side=tk.LEFT)
        ttk.Label(per, text="  しきい値:").pack(side=tk.LEFT)
        self.ent_thresholds = ttk.Entry(per, textvariable=self.var_thresholds, width=18)
        self.ent_thresholds.pack(side=tk.LEFT)
        ttk.Label(per, text="例: D100>80, D200<=10（超えたら通知）", style="Hint.TLabel").pack(
            side=tk.LEFT, padx=(4, 0)
        )

        ttk.Radiobutton(
            mode,
            text="フルスキャン（工場停止時のみ推奨）",
            value="full",
            variable=self.var_mode,
            command=self._on_mode_change,
        ).grid(row=6, column=0, columnspan=4, sticky=tk.W, pady=(8, 0))
        ttk.Label(
            mode, text="プロトコルごとの全デバイス範囲を読み取ります。時間がかかります。", style="Hint.TLabel"
        ).grid(row=7, column=0, columnspan=4, sticky=tk.W, padx=(20, 0))

        # データ型変換
        dt = ttk.LabelFrame(top, text="データ型変換（任意）", padding=8)
        dt.pack(side=tk.LEFT, fill=tk.BOTH)
        ttk.Label(dt, text="データ型").grid(row=0, column=0, sticky=tk.W)
        ttk.Combobox(
            dt,
            textvariable=self.var_data_type,
            values=["(変換なし)"] + list(DATA_TYPE_MAP.keys()),
            state="readonly",
            width=12,
        ).grid(row=0, column=1, sticky=tk.W, pady=2)
        ttk.Label(dt, text="バイト順").grid(row=1, column=0, sticky=tk.W)
        ttk.Combobox(
            dt, textvariable=self.var_byte_order, values=list(BYTE_ORDER_LABELS.values()), state="readonly", width=20
        ).grid(row=1, column=1, sticky=tk.W, pady=2)

        # 操作ボタン
        act = ttk.Frame(f)
        act.pack(fill=tk.X, pady=8)
        self.btn_collect = ttk.Button(act, text="▶ 収集開始", style="Primary.TButton", command=self._start_collect)
        self.btn_collect.pack(side=tk.LEFT)
        ttk.Label(act, text="※ 読み取り専用です。PLCへの書き込みは一切行いません。", style="Hint.TLabel").pack(
            side=tk.LEFT, padx=10
        )
        ttk.Checkbutton(act, text="NGのみ表示", variable=self.var_ng_only, command=self._refresh_data_tree).pack(
            side=tk.RIGHT
        )
        ttk.Label(act, textvariable=self.var_summary).pack(side=tk.RIGHT, padx=10)

        cols = ("address", "value", "hex", "converted", "status", "timestamp")
        headings = ("アドレス", "値 (10進)", "値 (16進)", "変換値", "ステータス", "取得時刻")
        widths = (100, 100, 90, 160, 150, 180)
        self.tree_data = self._make_tree(f, cols, headings, widths)
        self.tree_data.tag_configure("ng", background="#fdecea", foreground="#b71c1c")

    def _build_settings_tab(self) -> None:
        f = self.tab_settings
        net = ttk.LabelFrame(f, text="通信設定（PLCへの負荷を抑えるための待ち時間）", padding=10)
        net.pack(fill=tk.X)
        rows = [
            ("パケット送信間隔", self.var_packet_interval, "ミリ秒", "読み取り要求の間に入れる待ち時間（標準 50）"),
            ("リトライ待機時間", self.var_retry_interval, "ミリ秒", "エラー時に再試行するまでの待ち時間（標準 200）"),
            ("タイムアウト", self.var_timeout, "ミリ秒", "応答を待つ最大時間（標準 5000）"),
        ]
        for i, (label, var, unit, hint) in enumerate(rows):
            ttk.Label(net, text=label, width=16).grid(row=i, column=0, sticky=tk.W, pady=3)
            ttk.Entry(net, textvariable=var, width=8).grid(row=i, column=1, sticky=tk.W)
            ttk.Label(net, text=unit).grid(row=i, column=2, sticky=tk.W, padx=4)
            ttk.Label(net, text=hint, style="Hint.TLabel").grid(row=i, column=3, sticky=tk.W, padx=10)
        ttk.Button(net, text="標準値に戻す", command=self._reset_network_defaults).grid(
            row=len(rows), column=0, sticky=tk.W, pady=(8, 0)
        )

        out = ttk.LabelFrame(f, text="出力設定（CSVファイル）", padding=10)
        out.pack(fill=tk.X, pady=10)
        ttk.Label(out, text="保存先フォルダ", width=16).grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(out, textvariable=self.var_output_dir, width=60).grid(row=0, column=1, sticky=tk.W)
        ttk.Button(out, text="参照...", command=self._browse_output_dir).grid(row=0, column=2, padx=6)
        ttk.Label(out, text="文字コード", width=16).grid(row=1, column=0, sticky=tk.W, pady=(6, 0))
        enc = ttk.Frame(out)
        enc.grid(row=1, column=1, sticky=tk.W, pady=(6, 0))
        ttk.Radiobutton(
            enc, text="UTF-8（Excelでそのまま開ける・標準）", value="utf-8-sig", variable=self.var_encoding
        ).pack(side=tk.LEFT)
        ttk.Radiobutton(enc, text="UTF-8（BOMなし）", value="utf-8", variable=self.var_encoding).pack(
            side=tk.LEFT, padx=12
        )
        ttk.Radiobutton(enc, text="Shift-JIS", value="shift-jis", variable=self.var_encoding).pack(side=tk.LEFT)
        ttk.Checkbutton(
            out,
            text="三菱（SLMP）の X/Y/B/W は16進数のアドレスも出力する（例: X31 → X1F。CSV の address_hex 列と一覧表）",
            variable=self.var_hex_addresses,
            command=self._refresh_data_tree,
        ).grid(row=2, column=1, columnspan=2, sticky=tk.W, pady=(6, 0))
        ttk.Label(out, text="周期実行のCSV", width=16).grid(row=3, column=0, sticky=tk.W, pady=(6, 0))
        per = ttk.Frame(out)
        per.grid(row=3, column=1, columnspan=2, sticky=tk.W, pady=(6, 0))
        ttk.Radiobutton(per, text="周期ごとに1ファイル", value="per_cycle", variable=self.var_periodic_csv).pack(
            side=tk.LEFT
        )
        ttk.Radiobutton(
            per, text="1日1ファイルに追記（Excelでまとめて分析しやすい）", value="daily", variable=self.var_periodic_csv
        ).pack(side=tk.LEFT, padx=12)

        cfg = ttk.LabelFrame(f, text="設定ファイル（③〜⑤タブの設定を保存・読み込み）", padding=10)
        cfg.pack(fill=tk.X)
        ttk.Label(cfg, text="ファイル", width=16).grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(cfg, textvariable=self.var_settings_path, width=60).grid(row=0, column=1, sticky=tk.W)
        ttk.Button(cfg, text="参照...", command=self._browse_settings_file).grid(row=0, column=2, padx=6)
        btns = ttk.Frame(cfg)
        btns.grid(row=1, column=1, sticky=tk.W, pady=(6, 0))
        ttk.Button(btns, text="設定を保存", command=self._save_settings).pack(side=tk.LEFT)
        ttk.Button(btns, text="設定を読み込み", command=self._load_settings).pack(side=tk.LEFT, padx=8)
        ttk.Label(
            cfg,
            text="CLI でも同じファイルを使えます（plc_scanner.py -c ファイル名）。"
            "保存すると、ファイル内のコメントは消えます。ほかの項目（targets など）はそのまま残ります。",
            style="Hint.TLabel",
            wraplength=640,
            justify=tk.LEFT,
        ).grid(row=2, column=1, columnspan=2, sticky=tk.W, pady=(6, 0))

    # ----- 設定（③〜⑤タブ）と設定ファイル --------------------------------

    def _make_tree(
        self, parent: tk.Misc, cols: Sequence[str], headings: Sequence[str], widths: Sequence[int]
    ) -> ttk.Treeview:
        """スクロールバー付きの一覧表（Treeview）を作る"""
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=True)
        tree = ttk.Treeview(frame, columns=tuple(cols), show="headings", selectmode="browse")
        for c, h, w in zip(cols, headings, widths):
            tree.heading(c, text=h)
            tree.column(c, width=w, anchor=tk.W)
        ys = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=ys.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ys.pack(side=tk.RIGHT, fill=tk.Y)
        return tree

    # ----- 画面操作のイベント処理 -----------------------------------

    def _on_discover_scope_change(self) -> None:
        self.ent_ip_range.configure(state=tk.NORMAL if self.var_scope.get() == "range" else tk.DISABLED)

    def _on_mode_change(self) -> None:
        is_range = self.var_mode.get() == "range"
        st = tk.NORMAL if is_range else tk.DISABLED
        for w in (self.ent_start, self.ent_end, self.chk_periodic, self.ent_tags, self.btn_tag_list):
            w.configure(state=st)
        self.cb_device.configure(state="readonly" if is_range else tk.DISABLED)
        periodic_state = tk.NORMAL if is_range and self.var_periodic.get() else tk.DISABLED
        self.ent_interval.configure(state=periodic_state)
        self.ent_thresholds.configure(state=periodic_state)

    def _on_protocol_change(self, _event: Any = None) -> None:
        name = self.var_protocol.get()
        if name in Protocol.__members__:
            self.var_port.set(str(PROTOCOL_PORTS[Protocol[name]]))
        else:
            self.var_port.set("")

    def _reset_network_defaults(self) -> None:
        d = NetworkConfig()
        self.var_packet_interval.set(str(d.packet_interval_ms))
        self.var_retry_interval.set(str(d.retry_interval_ms))
        self.var_timeout.set(str(d.request_timeout_ms))

    def _browse_output_dir(self) -> None:
        path = filedialog.askdirectory(initialdir=self.var_output_dir.get() or ".")
        if path:
            self.var_output_dir.set(path)

    def _open_output_dir(self) -> None:
        path = Path(self.var_output_dir.get())
        path.mkdir(parents=True, exist_ok=True)
        try:
            if sys.platform.startswith("win"):
                os.startfile(str(path))  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path)])
        except Exception as e:
            messagebox.showerror("エラー", f"フォルダを開けませんでした:\n{e}")

    def _use_selected_plc(self) -> None:
        """探索結果で選択したPLCを「データ収集」タブの接続先に設定する"""
        sel = self.tree_plc.selection()
        if not sel:
            return
        plc = self.discovered[int(sel[0])]
        self.var_target.set(plc.ip_address)
        if plc.protocol:
            self.var_protocol.set(plc.protocol.name)
            self.var_port.set(str(plc.port or PROTOCOL_PORTS.get(plc.protocol) or ""))
        self.notebook.select(self.tab_collect)

    # ----- 入力値チェック ---------------------------------------

    def _int_field(self, var: tk.StringVar, label: str, minimum: int = 0) -> int:
        """入力欄の値を整数として取り出す。不正な値なら日本語のエラーメッセージで ValueError"""
        try:
            v = int(var.get().strip())
        except ValueError:
            raise ValueError(f"「{label}」には整数を入力してください。")
        if v < minimum:
            raise ValueError(f"「{label}」は {minimum} 以上にしてください。")
        return v

    def _network_config(self) -> NetworkConfig:
        return NetworkConfig(
            packet_interval_ms=self._int_field(self.var_packet_interval, "パケット送信間隔"),
            retry_interval_ms=self._int_field(self.var_retry_interval, "リトライ待機時間"),
            request_timeout_ms=self._int_field(self.var_timeout, "タイムアウト", minimum=100),
            max_concurrent=1,
        )

    def _exporter(self) -> CSVExporter:
        out = self.var_output_dir.get().strip() or DEFAULT_OUTPUT_DIR
        exporter = CSVExporter(out, self.var_encoding.get(), hex_addresses=self.var_hex_addresses.get())
        exporter.periodic_csv = self.var_periodic_csv.get()
        return exporter

    # ----- 処理の実行・停止 --------------------------------------

    def _set_busy(self, busy: bool, message: str = "") -> None:
        st = tk.DISABLED if busy else tk.NORMAL
        self.btn_discover.configure(state=st)
        self.btn_collect.configure(state=st)
        self.btn_stop.configure(state=tk.NORMAL if busy else tk.DISABLED)
        if busy:
            self.progress.configure(mode="indeterminate")
            self.progress.start(12)
        else:
            self.progress.stop()
            self.progress.configure(mode="determinate", value=0)
        if message:
            self.var_status.set(message)

    def _run_job(self, coro: Coroutine[Any, Any, Any], start_msg: str) -> None:
        """通信処理をワーカーに投入し、実行中はボタンを無効化する（同時実行は1件のみ）"""
        if self.worker.busy:
            messagebox.showinfo("実行中", "別の処理が実行中です。完了するか停止してから実行してください。")
            return
        self._set_busy(True, start_msg)
        self.worker.submit(coro, lambda exc: self.ui_queue.put(("done", exc)))

    def _stop(self) -> None:
        self.var_status.set("停止しています...")
        self.worker.cancel()

    def _progress_cb(self, message: str, current: int, total: int) -> None:
        """ワーカースレッドから呼ばれる進捗コールバック"""
        self.ui_queue.put(("progress", message, current, total))

    def _post(self, *item: Any) -> None:
        self.ui_queue.put(item)

    # ----- PLC探索 -----------------------------------------

    def _start_discovery(self) -> None:
        try:
            config = self._network_config()
            outputs = self._job_outputs()
        except ValueError as e:
            messagebox.showwarning("入力エラー", str(e))
            return
        ip_range = self.var_ip_range.get().strip() if self.var_scope.get() == "range" else None
        if self.var_scope.get() == "range" and not ip_range:
            messagebox.showwarning("入力エラー", "IP範囲を入力してください。")
            return
        if ip_range and ip_range_error(ip_range):
            messagebox.showwarning(
                "入力エラー",
                f"IP範囲を確認してください。\n{ip_range_error(ip_range)}\n\n"
                f"一度に探索できるのは最大 {MAX_IP_RANGE_HOSTS:,} 台（/16）までです。",
            )
            return
        self.tree_plc.delete(*self.tree_plc.get_children())
        self.discovered = []
        self.lbl_discover_count.configure(text="")
        self._run_job(
            self._discover_job(config, ip_range, self.var_broadcast.get(), self._exporter(), outputs),
            "PLCを探索しています...",
        )

    async def _discover_job(
        self,
        config: NetworkConfig,
        ip_range: Optional[str],
        use_broadcast: bool,
        exporter: CSVExporter,
        outputs: Optional[JobOutputs] = None,
    ) -> None:
        """ブロードキャスト探索とポートスキャンでPLCを探し、結果をCSVに保存する"""
        outputs = outputs or JobOutputs(None, None)
        audit = get_audit_logger()
        audit.log_discovery_start([ip_range] if ip_range else [])
        plcs: List[PLCInfo] = []
        if use_broadcast and ip_range:
            # Broadcasts go out on every network of this PC and would list
            # devices outside the range: the range is covered by the scan
            logging.info("IP範囲を指定しているため、UDPブロードキャスト探索は行いません（範囲内はスキャンで探します）")
        elif use_broadcast:
            self._post("status", "UDPブロードキャストで探索中...")
            try:
                plcs.extend(await BroadcastDiscovery(config).discover_all_broadcast())
            except Exception as e:  # 失敗しても続行
                logging.warning(f"ブロードキャスト探索に失敗しました（続行します）: {e}")

        self._post("status", f"{ip_range or '同一セグメント'} をスキャン中...")
        tcp_plcs = await discover_plcs(ip_range, config, self._progress_cb)
        # 同じIPでも応答したプロトコルごとに1行（複数プロトコル対応PLC・シミュレータ）。
        # TCPスキャンの結果（プロトコル確認済み・機器情報あり）を優先し、
        # ブロードキャストでのみ見つかった機器を追加する
        plcs = merge_discovery_results(tcp_plcs, plcs)
        audit.log_discovery_result(len(plcs), [p.to_dict() for p in plcs])

        path = None
        if plcs:
            try:
                path = exporter.export_discovery_results(plcs)
            except Exception as e:  # 一覧は表示する
                logging.error(f"探索結果CSVの書き込みに失敗しました: {e}")
            outputs.open_db()
            try:
                if outputs.db:
                    outputs.db.export_discovery_results(plcs)
            except Exception as e:
                logging.error(f"探索結果をデータベースに保存できませんでした: {e}")
            finally:
                outputs.close()
        self._post("discovered", plcs, path)
        await outputs.notify(lambda n: n.notify_discovery(len(plcs), [p.to_dict() for p in plcs]))

    def _show_discovered(self, plcs: List[PLCInfo], path: Optional[str]) -> None:
        self.discovered = plcs
        self.tree_plc.delete(*self.tree_plc.get_children())
        for i, p in enumerate(plcs):
            d = p.to_dict()
            self.tree_plc.insert(
                "",
                tk.END,
                iid=str(i),
                values=(
                    d["ip_address"],
                    d["manufacturer"] or "-",
                    d["model"] or "-",
                    d.get("cpu_type") or "-",
                    d.get("firmware_version") or "-",
                    d["protocol"] or "-",
                    d["port"],
                    d.get("read_method") or "-",
                    d["mac_address"] or "-",
                ),
            )
        if plcs:
            hosts = len({p.ip_address for p in plcs})
            count = f"{len(plcs)} 件を検出" + (f"（{hosts} 台）" if hosts != len(plcs) else "")
            self.lbl_discover_count.configure(text=count)
            self.var_status.set(f"探索完了: {count}  →  {path}")
            self.last_output_dir = Path(path).parent if path else None
        else:
            self.lbl_discover_count.configure(text="PLCは見つかりませんでした")
            hint = ""
            if self.var_scope.get() == "segment":
                hint = "（このPCで動かしているシミュレータは「IP範囲を指定」に 127.0.0.1 と入力して探索してください）"
            self.var_status.set("探索完了: PLCは見つかりませんでした" + hint)

    # ----- タグ一覧 -----------------------------------------

    def _pick_tags(self) -> None:
        """Logix のタグ一覧を読み、選んだタグをタグ欄に入れる（読み取りのみ）"""
        try:
            config = self._network_config()
            ip = self.var_target.get().strip()
            if not ip or target_address_error(ip):
                raise ValueError("タグ一覧を読むには、接続先PLCのIPアドレスを入力してください。")
            proto_name = self.var_protocol.get()
            if proto_name in Protocol.__members__ and proto_name != Protocol.ETHERNET_IP.name:
                raise ValueError("タグ一覧を読めるのは EtherNet/IP（Logix）だけです。プロトコルを確認してください。")
            port = self._int_field(self.var_port, "ポート", 1) if self.var_port.get().strip() else None
        except ValueError as e:
            messagebox.showwarning("入力エラー", str(e))
            return

        async def job():
            tags, reason = await fetch_tag_list(ip, port, config)
            self._post("tag_list", tags, reason)

        self._run_job(job(), f"{ip} のタグ一覧を読んでいます...")

    def _show_tag_list(self, tags: Optional[List[str]], reason: str) -> None:
        if not tags:
            self.var_status.set("タグ一覧を取得できませんでした")
            messagebox.showinfo("タグ一覧", reason)
            return
        self.var_status.set(f"タグ一覧: {len(tags)} 件")

        def apply(selected: List[str]) -> None:
            self.var_tags.set(", ".join(selected))

        TagPickerDialog(self.root, tags, parse_tag_list(self.var_tags.get()), apply)

    # ----- データ収集 -----------------------------------------

    def _start_collect(self) -> None:
        try:
            config = self._network_config()
            ip = self.var_target.get().strip()
            if not ip:
                raise ValueError("接続先PLCのIPアドレスを入力してください。")
            if target_address_error(ip):
                raise ValueError(
                    f"接続先PLCのIPアドレス（またはホスト名）が正しくありません: {ip}\n（例: 192.168.1.10）"
                )
            proto_name = self.var_protocol.get()
            protocol = Protocol[proto_name] if proto_name in Protocol.__members__ else None
            port = self._int_field(self.var_port, "ポート", 1) if self.var_port.get().strip() else None

            mode = self.var_mode.get()
            device_type = DeviceType(self.var_device.get())
            tags = parse_tag_list(self.var_tags.get()) if mode == "range" else []
            if tags and protocol not in (None, Protocol.ETHERNET_IP):
                raise ValueError(
                    "タグを読めるのは EtherNet/IP（Logix・オムロン NJ/NX）だけです。\n"
                    "プロトコルを「ETHERNET_IP」か「自動検出」にするか、タグ欄を空にしてください。"
                )
            # The address fields are used by a range scan of a device only:
            # leftover text in them must not stop a full scan or a tag read
            start = end = 0
            if mode == "range" and not tags:
                start = self._int_field(self.var_start, "開始アドレス")
                end = self._int_field(self.var_end, "終了アドレス")
            if mode == "range" and not tags and end < start:
                raise ValueError("終了アドレスは開始アドレス以上にしてください。")
            if mode == "range" and not tags and end - start + 1 > MAX_RANGE_POINTS:
                raise ValueError(
                    f"一度に読み取れるのは {MAX_RANGE_POINTS:,} 点までです"
                    f"（指定: {end - start + 1:,} 点）。範囲を分けて実行してください。"
                )
            interval = 0.0
            if mode == "range" and self.var_periodic.get():
                try:
                    interval = float(self.var_interval.get())
                except ValueError:
                    raise ValueError("「周期」には数値（秒）を入力してください。")
                if not math.isfinite(interval):
                    raise ValueError("「周期」には数値（秒）を入力してください。")
                if interval < MIN_PERIODIC_INTERVAL_SEC:
                    raise ValueError(f"周期は {MIN_PERIODIC_INTERVAL_SEC:g} 秒以上にしてください（PLC負荷対策）。")
            thresholds: List[Threshold] = []
            if interval:
                try:
                    thresholds = parse_thresholds([self.var_thresholds.get()])
                except ValueError as e:
                    raise ValueError(f"「しきい値」の書き方が正しくありません。\n例: D100>80, D200<=10\n\n{e}")
            outputs = self._job_outputs()
        except ValueError as e:
            messagebox.showwarning("入力エラー", str(e))
            return

        if mode == "full" and not messagebox.askyesno(
            "フルスキャンの確認",
            "フルスキャンは全デバイス範囲を読み取るため、通信量が多く時間がかかります。\n\n"
            "工場停止中（メンテナンス時）での実行を推奨します。\n生産中の場合は「範囲指定」モードを使ってください。\n\n"
            "フルスキャンを開始しますか？",
            icon=messagebox.WARNING,
        ):
            return

        dt_name = self.var_data_type.get()
        data_type = DATA_TYPE_MAP.get(dt_name)
        bo_key = next((k for k, v in BYTE_ORDER_LABELS.items() if v == self.var_byte_order.get()), "little")
        byte_order = BYTE_ORDER_MAP.get(bo_key, ByteOrder.LITTLE_ENDIAN)

        self._last_points = []
        self._refresh_data_tree()
        self.var_summary.set("")
        self._run_job(
            self._collect_job(
                config,
                ip,
                protocol,
                port,
                mode,
                device_type,
                start,
                end,
                interval,
                data_type,
                byte_order,
                self._exporter(),
                outputs,
                tags=tags,
                thresholds=thresholds,
            ),
            f"{ip} に接続しています...",
        )

    async def _collect_job(
        self,
        config: NetworkConfig,
        ip: str,
        protocol: Optional[Protocol],
        port: Optional[int],
        mode: str,
        device_type: DeviceType,
        start: int,
        end: int,
        interval: float,
        data_type: Optional[DataType],
        byte_order: ByteOrder,
        exporter: CSVExporter,
        outputs: Optional[JobOutputs] = None,
        tags: Optional[List[str]] = None,
        thresholds: Optional[List[Threshold]] = None,
    ) -> None:
        """指定PLCに接続してデータを読み取り、CSVに保存する（周期実行時は停止まで繰り返す）"""
        outputs = outputs or JobOutputs(None, None)
        # プロトコル決定（自動検出または手動指定）
        if protocol is None:
            self._post("status", f"{ip} のプロトコルを自動検出中...")
            # With a port, the protocols are tried on that port (as the CLI
            # does): detecting on the standard ports and then overwriting
            # the port paired the protocol with a port it was not seen on
            detected = await PLCDiscovery(config, port=port)._probe_host(ip)
            if detected and detected.protocol:
                plc = detected
                logging.info(f"プロトコルを検出しました: {detected.protocol.name}")
            else:
                await outputs.notify(lambda n: n.notify_error(f"{ip}: no PLC protocol answered", plc_ip=ip))
                raise RuntimeError(
                    f"{ip} のプロトコルを検出できませんでした。\n"
                    "PLCの電源・ネットワーク接続を確認するか、プロトコルを手動で選択してください。"
                )
        else:
            plc = PLCInfo(ip_address=ip, protocol=protocol, port=port or PROTOCOL_PORTS.get(protocol))

        # The requested ranges / tags (None: full scan), shared with the CLI
        items: Optional[List[ScanItem]] = (
            None if mode == "full" else ([TagRange(tags)] if tags else [DeviceRange(device_type, start, end)])
        )
        protocol_name = plc.protocol.name if plc.protocol else "UNKNOWN"
        collector = PLCDataCollector(plc, config)
        collector.set_progress_callback(self._progress_cb)
        connected = await collector.connect()
        get_audit_logger().log_connect(plc.ip_address, protocol_name, plc.port or 0, connected, collector.connect_error)
        if not connected:
            if not interval or collector.connect_error:
                await collector.disconnect()
                # Still save every requested address as NG_COMM_ERROR (CSV and
                # table), so the result shows what could not be read
                unread = unreached_points(plc.protocol, items)
                self._last_protocol = plc.protocol
                saved = ResultWriter(plc, exporter).export_points(unread)
                stats = {
                    "total_points": len(unread),
                    "success_count": 0,
                    "success_rate": success_rate_text(0, len(unread)),
                }
                self._post("data", unread, stats, saved, None, 1)
                await outputs.notify(
                    lambda n: n.notify_error(f"Failed to connect to {ip}:{plc.port} ({protocol_name})", plc_ip=ip)
                )
                message = f"{ip}:{plc.port} ({protocol_name}) に接続できませんでした。"
                if saved:
                    message += f"\n\n読めなかったアドレスを NG_COMM_ERROR として保存しました:\n{saved}"
                raise RuntimeError(message)
            # Periodic monitoring started while the PLC is off or restarting:
            # keep going; every cycle retries the connection and records the
            # addresses as communication errors until the PLC answers
            logging.warning(f"{ip}:{plc.port} ({protocol_name}) に接続できません。周期ごとに再接続を試みます。")
        loop = asyncio.get_running_loop()
        self._last_protocol = plc.protocol
        outputs.open_db()
        # Write failures (e.g. CSV opened in Excel) are logged and the
        # collection continues; unwritten denied addresses are retried
        daily = bool(interval) and getattr(exporter, "periodic_csv", "per_cycle") == "daily"
        writer = ResultWriter(plc, exporter, db_exporter=outputs.db, daily=daily)
        runner = CycleRunner(
            items,
            data_type=data_type,
            byte_order=byte_order,
            notifier=outputs.notifier,
            notify=outputs.notify,
            thresholds=ThresholdMonitor(thresholds or []),
        )
        target = f"{ip}:{plc.port} ({protocol_name})"
        job_started = loop.time()
        iteration = 0
        points: List[DataPoint] = []
        audit = get_audit_logger()
        audit.log_scan_start(ip, mode, ["ALL"] if items is None else [str(item) for item in items])
        try:
            while True:
                iteration += 1
                started = loop.time()
                if interval:
                    self._post("status", f"周期実行 {iteration} 回目: 読み取り中...")
                points, path, denied_path = await runner.read(collector, writer)
                self._post("data", points, collector.get_statistics(), path, denied_path, iteration)

                if not interval:
                    break

                # Periodic monitoring: an error notification when the PLC stops
                # answering (once per outage) and the periodic status report
                # Connected is not enough: FINS/UDP has no connection to lose
                unreachable = not collector.is_connected or not plc_answered(points)
                await runner.track_outage(target, not unreachable, ip)
                await runner.check_thresholds(target, points, ip)
                await runner.report_if_due({ip: points}, [ip] if unreachable else [], iteration)

                wait = next_cycle_wait(interval, started)
                self._post("status", f"周期実行 {iteration} 回目完了。{wait:.1f} 秒後に次回実行（停止ボタンで終了）")
                await asyncio.sleep(wait)
        except asyncio.CancelledError:
            # Stopped by the user: release the PLC first - a webhook that is
            # slow to answer must not keep the session open - then report
            # what was collected
            await collector.disconnect()
            await runner.drain()  # notifications a slow webhook is still receiving
            await PLCScannerApp._notify_collect_done(
                outputs, ip, points, iteration, loop.time() - job_started, interrupted=True
            )
            raise
        finally:
            # The last cycle, as the CLI records it
            ok = sum(1 for point in points if point.status == StatusCode.OK)
            audit.log_scan_complete(ip, len(points), ok, len(points) - ok, (loop.time() - job_started) * 1000)
            await collector.disconnect()
            outputs.close()
        await PLCScannerApp._notify_collect_done(outputs, ip, points, iteration, loop.time() - job_started)

    @staticmethod
    async def _notify_collect_done(
        outputs: JobOutputs,
        ip: str,
        points: List[DataPoint],
        iteration: int,
        duration: float,
        interrupted: bool = False,
    ) -> None:
        ok = sum(1 for p in points if p.status == StatusCode.OK)
        all_ok = bool(points) and ok == len(points)
        await outputs.notify(
            lambda n: n.notify_scan_complete(
                1,
                1 if all_ok else 0,
                0 if all_ok else 1,
                duration,
                mode="gui",
                interrupted=interrupted,
                cycles=iteration,
                ok_points=ok,
                ng_points=len(points) - ok,
                plc_ip=ip,
            )
        )

    def _show_data(
        self, points: List[DataPoint], stats: Dict, path: Optional[str], denied_path: Optional[str], iteration: int
    ) -> None:
        self._last_points = points
        self._refresh_data_tree()
        ok = stats.get("success_count", 0)
        total = stats.get("total_points", 0)
        self.var_summary.set(f"全 {total} 件   OK {ok} 件   NG {total - ok} 件   成功率 {stats.get('success_rate')}")
        prefix = f"[{iteration}回目] " if iteration > 1 or self.var_periodic.get() else ""
        if path:
            self.last_output_dir = Path(path).parent
            self.var_status.set(f"{prefix}収集完了 → {path}")
        else:
            self.var_status.set(f"{prefix}収集完了（データなし）")
        if denied_path:
            logging.info(f"アクセス不可アドレスを記録しました: {denied_path}")

    def _refresh_data_tree(self) -> None:
        """収集結果を一覧表に表示する（NGのみ表示・最大表示件数を反映）"""
        tree = self.tree_data
        tree.delete(*tree.get_children())
        points = self._last_points
        if self.var_ng_only.get():
            points = [p for p in points if p.status != StatusCode.OK]
        show_hex = self.var_hex_addresses.get() and self._last_protocol == Protocol.SLMP
        for i, p in enumerate(points[:MAX_DISPLAY_ROWS]):
            ng = p.status != StatusCode.OK
            address = p.address
            if show_hex and melsec_address(p.address) != p.address:
                address = f"{p.address} ({melsec_address(p.address)})"
            tree.insert(
                "",
                tk.END,
                iid=str(i),
                tags=("ng",) if ng else (),
                values=(
                    address,
                    "" if p.value is None else p.value,
                    p.raw_hex or "",
                    p.display_value or ("" if p.converted_value is None else p.converted_value),
                    STATUS_LABELS.get(p.status, p.status.value),
                    p.timestamp,
                ),
            )
        if len(points) > MAX_DISPLAY_ROWS:
            tree.insert(
                "",
                tk.END,
                iid="more",
                values=(
                    f"… 他 {len(points) - MAX_DISPLAY_ROWS} 件",
                    "",
                    "",
                    "全件はCSVファイルに保存されています",
                    "",
                    "",
                ),
            )

    # ----- キュー処理（GUIスレッドで画面を更新） --------------------------

    def _poll_queue(self) -> None:
        """ワーカーからの通知を100msごとに取り出して画面に反映する"""
        try:
            while True:
                item = self.ui_queue.get_nowait()
                try:
                    self._handle_ui_item(item)
                except Exception:
                    # One notification that cannot be shown must not end the
                    # polling: the window would stay "running" for good, with
                    # Start disabled and the log frozen
                    logging.getLogger(__name__).exception(f"画面の更新に失敗しました（{item[0]}）")
                    if item[0] == "done":
                        self._set_busy(
                            False, "処理は終了しましたが、結果の表示に失敗しました（ログを確認してください）"
                        )
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self._poll_queue)

    def _handle_ui_item(self, item: tuple) -> None:
        kind = item[0]
        if kind == "log":
            self._append_log(item[1], item[2])
        elif kind == "status":
            self.var_status.set(item[1])
        elif kind == "progress":
            _, msg, cur, total = item
            self.var_status.set(msg)
            if total:
                self.progress.stop()
                self.progress.configure(mode="determinate", maximum=total, value=cur)
        elif kind == "discovered":
            self._show_discovered(item[1], item[2])
        elif kind == "data":
            self._show_data(*item[1:])
        elif kind == "tag_list":
            self._show_tag_list(item[1], item[2])
        elif kind == "db_status":
            self.var_db_status.set(item[1])
        elif kind == "done":
            # From here on a new job may be started: its buttons are set by
            # this very handler
            self.worker.acknowledge()
            self._on_job_done(item[1])

    def _on_job_done(self, exc: Optional[BaseException]) -> None:
        """処理の終了（正常・停止・エラー）を画面に反映する"""
        current = self.var_status.get()
        self._set_busy(False)
        if isinstance(exc, asyncio.CancelledError):
            self.var_status.set("停止しました（完了した収集分のみCSVに保存されています）")
            logging.info("ユーザー操作により停止しました")
        elif exc is not None:
            self.var_status.set("エラーで終了しました")
            logging.error(str(exc))
            messagebox.showerror("エラー", str(exc))
        else:
            self.var_status.set(current)

    def _append_log(self, level: str, text: str) -> None:
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, text + "\n", level)
        # ログが肥大化しないよう古い行を削除
        lines = int(self.log_text.index("end-1c").split(".")[0])
        if lines > 2000:
            self.log_text.delete("1.0", f"{lines - 2000}.0")
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _on_close(self) -> None:
        """ウィンドウを閉じる。実行中なら確認してから停止する"""
        if self.worker.busy and not messagebox.askyesno("終了確認", "処理を実行中です。停止して終了しますか？"):
            return
        self.worker.shutdown()
        self.root.destroy()


APP_NAME = "PLC Discovery"


def set_macos_app_name(name: str) -> None:
    """
    Show the application as `name` instead of "Python" in the macOS menu bar
    and Dock (Tk takes the name from the process bundle, which is Python's).

    Sets CFBundleName in the main bundle's info dictionary through the
    Objective-C runtime (ctypes, no extra packages) before Tk starts.
    Does nothing on other platforms or if anything fails.
    """
    if sys.platform != "darwin":
        return
    try:
        import ctypes
        import ctypes.util

        objc_path, foundation_path = ctypes.util.find_library("objc"), ctypes.util.find_library("Foundation")
        if not objc_path or not foundation_path:
            return
        objc = ctypes.cdll.LoadLibrary(objc_path)
        ctypes.cdll.LoadLibrary(foundation_path)
        objc.objc_getClass.restype = ctypes.c_void_p
        objc.objc_getClass.argtypes = [ctypes.c_char_p]
        objc.sel_registerName.restype = ctypes.c_void_p
        objc.sel_registerName.argtypes = [ctypes.c_char_p]
        send = ctypes.cast(objc.objc_msgSend, ctypes.c_void_p).value
        if send is None:
            return
        msg0 = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)(send)
        msg_str = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p)(send)
        msg2 = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)(send)
        sel = objc.sel_registerName

        def nsstring(text: str) -> Any:
            return msg_str(objc.objc_getClass(b"NSString"), sel(b"stringWithUTF8String:"), text.encode("utf-8"))

        bundle = msg0(objc.objc_getClass(b"NSBundle"), sel(b"mainBundle"))
        info = msg0(bundle, sel(b"infoDictionary"))  # mutable in practice
        if info:
            msg2(info, sel(b"setObject:forKey:"), nsstring(name), nsstring("CFBundleName"))
    except Exception as e:  # cosmetic only: never prevent the GUI from starting
        logging.getLogger(__name__).debug(f"Could not set the macOS application name: {e}")


def main() -> None:
    set_macos_app_name(APP_NAME)
    root = tk.Tk(className=APP_NAME)
    PLCScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
